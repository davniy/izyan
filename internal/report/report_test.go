package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func symRef(pkg, s string) domain.SymbolRef {
	return domain.SymbolRef{Package: pkg, Symbol: s}
}

// h2Headings returns the report's `## ` section titles in order.
func h2Headings(md string) []string {
	var out []string
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "## ") {
			out = append(out, line)
		}
	}
	return out
}

// minimalCase is a bare case with an EXPLOITABLE verdict and a resolved
// applicability record — enough to exercise every human section.
func minimalCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: "case-min",
		Vulnerability: domain.Vulnerability{
			ID:            "GO-2026-0001",
			Module:        "example.com/mod",
			Summary:       "parsing defect in ModParse",
			FixedVersions: []string{"v1.2.0"},
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/mod/vulnpkg"},
			},
			BaseSeverity:   "HIGH",
			BaseScore:      7.5,
			SeveritySource: "OSV",
			ScoreSource:    "OSV",
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "1234567890ab",
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.1.0",
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		RootCause: &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{
				{Package: "example.com/mod/vulnpkg", Symbol: "Parse", Role: domain.RootCauseSink, Mechanism: "out-of-bounds read"},
			},
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
			Reason:  "all mandatory exploit conditions are satisfied",
		},
	}
}

// sampleAuditCase carries one item of every audit-tracked structure so the
// technical report exercises all of its sections.
func sampleAuditCase() *domain.AnalysisCase {
	c := minimalCase()
	c.Verdict = &domain.VerdictResult{
		Verdict:      domain.VerdictNoExploitPathFound,
		Reason:       "mandatory exploit condition is proven false",
		ConditionIDs: []domain.ConditionID{"C-LOCUS"},
		EvidenceIDs:  []domain.EvidenceID{"EV-CLM-1"},
		Limitations:  []string{"verdict limitation"},
	}
	c.Claims = []domain.Claim{
		{
			ID:          "CLM-1",
			ConditionID: "C-LOCUS",
			Producer:    "locus-eval",
			Result:      domain.ClaimFalse,
			Falsifier:   "locus-package-absent",
			Explanation: "locus packages absent from build graph",
			EvidenceIDs: []domain.EvidenceID{"EV-CLM-1"},
			Limitations: []string{"claim limitation"},
			NegativeVerification: &domain.NegativeVerification{
				Status:      domain.NegativeVerified,
				Notes:       "package graph checked",
				EvidenceIDs: []domain.EvidenceID{"EV-PKG-1"},
				Limitations: []string{"nv limitation"},
			},
		},
		{
			ID:          "CLM-2",
			ConditionID: "C-PEER-INPUT",
			Producer:    "ingress-eval",
			Result:      domain.ClaimUnknown,
			Explanation: "payload origin unresolved",
			Limitations: []string{"dup limitation", "claim limitation"},
		},
	}
	c.Exploit = &domain.ExploitModel{
		Class:  "MEMORY_CORRUPTION",
		Impact: "process crash",
		MandatoryConditions: []domain.Condition{
			{ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable, Mandatory: true, Description: "locus package linked"},
			{ID: "C-PEER-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true, Description: "peer input controlled"},
		},
		SupportingFactors: []domain.Condition{
			{ID: "C-EXPOSURE", Kind: domain.ConditionConfiguration, Description: "network reachable"},
		},
		LocusSubjects:    []domain.SymbolRef{symRef("example.com/mod/vulnpkg", "Parse")},
		NonLocusBasis:    []domain.LocusDecision{{Symbol: symRef("example.com/mod/vulnpkg", "Helper"), Authority: "эксперт", Basis: "safe helper"}},
		ProposedNonLocus: []domain.LocusDecision{{Symbol: symRef("example.com/mod/vulnpkg", "Other"), Authority: "machine-proposal", Basis: "enabler-candidate"}},
		LocusAnnotations: []domain.LocusDecision{{Symbol: symRef("example.com/mod/vulnpkg", "Parse"), Authority: "machine-annotation", Basis: "faulting site"}},
		UnresolvedSubjects: []domain.SymbolRef{
			symRef("example.com/mod/vulnpkg", "Missing"),
		},
		AbsentSubjects: []domain.SymbolRef{
			symRef("example.com/mod/absent", "Gone"),
		},
		EvidenceIDs: []domain.EvidenceID{"EV-CLM-1"},
	}
	c.NonLocusBasis = []domain.LocusDecision{
		{Symbol: symRef("example.com/mod/vulnpkg", "CaseHelper"), Authority: "эксперт", Basis: "case-level exclusion"},
	}
	c.EvidenceGraph = domain.EvidenceGraph{
		Evidence: []domain.Evidence{
			{ID: "EV-PKG-1", Kind: domain.EvidencePackageList, Content: `{"ImportPath":"example.com/mod/vulnpkg"}`},
			{ID: "EV-CLM-1", Kind: domain.EvidenceGovulncheck, Tool: "govulncheck", ToolVersion: "v1.0.4", Command: "govulncheck ./...", Content: "no call paths", Limitations: []string{"evidence limitation"}},
			{ID: "EV-RUNTIME-1", Kind: domain.EvidenceRuntime, Source: "runtime-env", Content: "go version go1.26.1"},
			{ID: "EV-BUILD-1", Kind: domain.EvidenceBuild, Source: "go build", Command: "go build ./...", Content: "build successful"},
			{ID: "EV-TEST-1", Kind: domain.EvidenceTest, Source: "go test", Command: "go test ./...", Content: "all tests pass"},
		},
		Exposures: []domain.ExposureFact{
			{
				CallSite:      domain.CallSite{File: "main.go", Line: 42},
				Direction:     "inbound",
				Kind:          "listener",
				Target:        "net/http.ListenAndServe",
				Address:       ":8080",
				AddressSource: "literal",
				Scope:         domain.ScopeAllInterfaces,
				Owner:         "svc",
			},
		},
		Entrypoints: []domain.Entrypoint{
			{CallSite: domain.CallSite{File: "main.go", Line: 10, Function: "main"}, Kind: "http", Detail: "serve", Exposed: true},
		},
		DataFlows: []domain.DataFlow{
			{
				ConditionID:     "C-PEER-INPUT",
				Source:          domain.CallSite{Function: "ReadAll", File: "io.go", Line: 10},
				Sink:            domain.CallSite{Function: "Parse", Callee: "vulnpkg.Parse", File: "parser.go", Line: 20},
				Transformations: []domain.CallSite{{Function: "Trim", File: "t.go", Line: 5}},
				Arg:             0,
				Origin:          domain.OriginExternalUntrusted,
				Summary:         "query param flows to sink",
				PayloadUnproven: true,
			},
		},
		CallPaths: []domain.CallPath{
			{
				ConditionID: "C-LOCUS",
				EvidenceID:  "EV-CLM-1",
				Frames: []domain.CallSite{
					{Package: "main", Function: "main", File: "main.go", Line: 20},
					{Package: "example.com/mod/vulnpkg", Function: "Parse", File: "parse.go", Line: 90},
				},
			},
		},
		IngressClosures: []domain.IngressClosure{
			{
				ConditionID: "C-PEER-INPUT",
				Module:      "example.com/mod",
				Complete:    false,
				Items: []domain.IngressItem{
					{
						CallSite: domain.CallSite{File: "handler.go", Line: 15},
						Kind:     domain.IngressBoundaryArg,
						Callee:   "vulnpkg.Parse",
						Arg:      0,
						Origin:   domain.OriginUnknown,
						Detail:   "body argument",
					},
				},
				Blockers: []string{"opaque dispatch"},
			},
		},
		SinkClosures: []domain.SinkClosure{
			{
				ConditionID: "C-PEER-INPUT",
				Module:      "example.com/mod",
				Basis:       "advisory-declared sink set",
				Complete:    true,
				Sites: []domain.SinkSite{
					{
						CallSite: domain.CallSite{File: "use.go", Line: 30},
						Sink:     "example.com/mod/vulnpkg.Parse",
						Arg:      1,
						Live:     true,
						Origin:   domain.OriginConstant,
						Detail:   "constant input",
					},
				},
			},
		},
		ToolExecutions: []domain.ToolExecution{
			{
				ID:           "TX-001",
				Tool:         "govulncheck",
				Version:      "v1.0.4",
				Dir:          "/repo",
				Args:         []string{"-json", "./..."},
				ExitCode:     0,
				DurationMs:   150,
				StdoutSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				StderrSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		Runtime:         []domain.EvidenceID{"EV-RUNTIME-1"},
		Limitations:     []string{"graph limitation"},
		ToolLimitations: []string{"tool limitation"},
	}
	c.Hypotheses = []domain.Hypothesis{
		{ID: "H-1", ConditionID: "C-LOCUS", Status: domain.HypothesisRejected, Statement: "package not linked", Notes: "checked"},
	}
	c.Reviews = []domain.Review{
		{
			ID:     "REV-1",
			Result: domain.ReviewAccept,
			Findings: []domain.ReviewFinding{
				{Severity: "LOW", TargetType: "claim", TargetID: "C-LOCUS", Problem: "minor verification note"},
			},
		},
	}
	c.CVEAnalysis = &domain.CVEAnalysisProposal{
		ID:       "CVE-A-1",
		Revision: 2,
		Binding: domain.AnalysisBinding{
			AdvisoryID:           "GO-2026-0001",
			AdvisoryHash:         "deadbeef",
			Module:               "example.com/mod",
			ResolvedVersion:      "v1.1.0",
			VulnerableSourceHash: "srchash",
		},
		Mechanisms: []domain.DefectMechanism{
			{ID: "M-1", Summary: "bounds check missing", FaultingSites: []string{"vulnpkg.Parse"}, PatchExplanation: "add bound"},
		},
		Preconditions:  []string{"crafted input"},
		Confidence:     "HIGH",
		EvidenceIDs:    []domain.EvidenceID{"EV-CLM-1"},
		ToolIterations: 3,
	}
	c.CVEAnalysisBundle = &domain.CVESourceBundle{
		ManifestStatus: domain.ManifestComplete,
		Artifacts: []domain.SourceArtifact{
			{ID: "ART-1", Side: "vulnerable", URI: "file:///src", Hash: "arthash", Status: "FETCHED", EvidenceID: "EV-CLM-1", Limitations: []string{"artifact limitation"}},
		},
		Limitations: []string{"bundle limitation"},
	}
	c.StrategyPlan = &domain.StrategyPlan{
		ID:               "SP-1",
		SelectedStrategy: "direct-verification",
		Obligations:      []string{"prove reachability"},
	}
	c.SemanticReview = &domain.SemanticReview{
		Passed:   true,
		Reviewer: "llm-reviewer",
		Findings: []string{"mechanism consistent"},
	}
	c.Justification = &domain.AnalysisJustification{
		Verdict:            domain.VerdictNoExploitPathFound,
		ExecutiveSummary:   "packages absent",
		TechnicalMechanism: "no path",
		TrackerCommentRu:   "комментарий",
		VerifiedFacts:      []string{"fact one"},
		HumanRemainder: []domain.HumanRemainderItem{
			{Obligation: "check deploy", Question: "is production isolated?", EvidenceRef: "EV-CLM-1"},
		},
	}
	c.Profiles = []domain.ProfileVerdict{
		{
			Profile:        domain.ProfileZeroTrust,
			Verdict:        domain.VerdictExploitable,
			Reason:         "all mandatory exploit conditions are satisfied",
			Priority:       domain.PriorityP1,
			SLA:            "7d",
			IsTargetActual: true,
		},
		{
			Profile:        domain.ProfileClusterPerimeter,
			Verdict:        domain.VerdictNoExploitPathFound,
			Reason:         "trusted-infrastructure",
			Falsifier:      domain.FalsifierTrustedInfrastructure,
			Priority:       domain.PriorityDismissed,
			SLA:            "none",
			IsTargetActual: false,
		},
	}
	c.DetectedPerimeter = domain.PerimeterPublic
	c.PerimeterRationale = "public exposure detected: inbound listener :8080"
	return c
}

func TestRemediationPicksMinFixAboveResolved(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:            "GO-X",
			Module:        "example.com/mod",
			FixedVersions: []string{"v1.5.0", "v1.4.0", "v2.0.0"},
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.4.0",
		},
	}
	r := remediation(c)
	if !strings.Contains(r, "v1.5.0") || !strings.Contains(r, "go get example.com/mod@v1.5.0") {
		t.Fatalf("remediation=%q", r)
	}
}

func TestRemediationEmptyWhenNotAffected(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "m", FixedVersions: []string{"v1.0.0"}},
		Affected:      &domain.AffectedResult{VersionAffected: domain.ClaimFalse},
	}
	if remediation(c) != "" {
		t.Fatal("no remediation expected when not affected")
	}
}

func TestRemediationNoFixPublished(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "m"},
		Affected:      &domain.AffectedResult{VersionAffected: domain.ClaimTrue, ResolvedVersion: "v9.9.9"},
	}
	if !strings.Contains(remediation(c), "No fixed version") {
		t.Fatal("expected no-fix message")
	}
}

func TestMachineAssessment(t *testing.T) {
	sym := func(pkg, s string) domain.SymbolRef {
		return domain.SymbolRef{Package: pkg, Symbol: s}
	}
	base := func(content string) *domain.AnalysisCase {
		return &domain.AnalysisCase{
			Exploit: &domain.ExploitModel{
				LocusSubjects: []domain.SymbolRef{
					sym("x/internal/transport", "A"),
					sym("x/internal/transport", "B"),
					sym("x/internal/xds/server", "Site"),
				},
				ProposedNonLocus: []domain.LocusDecision{
					{Symbol: sym("x/internal/transport", "A"), Authority: "machine-proposal", Basis: "enabler-candidate"},
				},
				LocusAnnotations: []domain.LocusDecision{
					{Symbol: sym("x/internal/transport", "B"), Authority: "machine-annotation", Basis: "guarded-site; fix hunk guards the faulting operation"},
				},
			},
			EvidenceGraph: domain.EvidenceGraph{
				Evidence: []domain.Evidence{{
					Kind:    domain.EvidencePackageList,
					Content: content,
				}},
			},
		}
	}
	t.Run("linked packages split proposals from flagged symbols", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x"}`)
		n := machineAssessment(c)
		if !strings.Contains(n, "УСЛОВНО") ||
			!strings.Contains(n, "**рекомендуется исключить**") ||
			!strings.Contains(n, "**исключение не рекомендуется**") ||
			!strings.Contains(n, "x/internal/xds/server.Site") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("all-proposed linked symbols give dismissible pending approval", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x"}`)
		c.Exploit.ProposedNonLocus = append(c.Exploit.ProposedNonLocus,
			domain.LocusDecision{Symbol: sym("x/internal/transport", "B"), Authority: "machine-proposal"})
		if n := machineAssessment(c); !strings.Contains(n, "ОТКЛОНИТЬ ПОСЛЕ ПОДТВЕРЖДЕНИЯ") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("all locus packages absent is dismissible outright", func(t *testing.T) {
		c := base(`{"ImportPath":"x"}`)
		if n := machineAssessment(c); !strings.Contains(n, "**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ**") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("missing package-list evidence cannot be assessed", func(t *testing.T) {
		c := base("")
		c.EvidenceGraph.Evidence = nil
		if n := machineAssessment(c); !strings.Contains(n, "нельзя") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("exploitable verdict suppresses dismissal and affirms exploitation", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x"}`)
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictExploitable}
		nRU := machineAssessment(c, true)
		if strings.Contains(nRU, "ОТКЛОНИТЬ") || !strings.Contains(nRU, "Уязвимость подтверждена и эксплуатируема") {
			t.Fatalf("unexpected RU assessment for exploitable: %q", nRU)
		}
		nEN := machineAssessment(c, false)
		if strings.Contains(nEN, "DISMISSIBLE") || !strings.Contains(nEN, "confirmed exploitable") {
			t.Fatalf("unexpected EN assessment for exploitable: %q", nEN)
		}
	})
	t.Run("machine assessment lives in the audit, not the human report", func(t *testing.T) {
		c := base(`{"ImportPath":"x"}`)
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictNoExploitPathFound}
		aud := AuditMarkdown(c)
		if !strings.Contains(aud, "## Внутренние машинные гипотезы") ||
			!strings.Contains(aud, "не изменяет финальный вердикт") {
			t.Fatalf("audit missing machine assessment section:\n%s", aud)
		}
		human := Markdown(c)
		if strings.Contains(human, "МОЖНО ОТКЛОНИТЬ") || strings.Contains(human, "Внутренние машинные гипотезы") {
			t.Fatalf("human report leaked machine assessment:\n%s", human)
		}
	})
}

func TestTrackerRationale(t *testing.T) {
	t.Run("no exploit path found renders verdict cause and update", func(t *testing.T) {
		c := &domain.AnalysisCase{
			ID: "case-001",
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-84445",
				Module:        "google.golang.org/grpc",
				Summary:       "паника в xDS routing interceptor при пустом authority",
				FixedVersions: []string{"v1.82.2", "v1.83.2"},
				AffectedPackages: []domain.AffectedPackage{
					{Path: "google.golang.org/grpc/internal/xds"},
					{Path: "google.golang.org/grpc/internal/transport"},
				},
			},
			Product: domain.ProductSnapshot{
				Repository: "example.com/demo-service",
				Commit:     "74224f4d12345678",
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.80.0",
			},
			Exploit: &domain.ExploitModel{
				MandatoryConditions: []domain.Condition{
					{ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable, Mandatory: true, Description: "defect locus linked into build"},
				},
			},
			Claims: []domain.Claim{
				{
					ConditionID: "C-LOCUS",
					Result:      domain.ClaimFalse,
					Falsifier:   domain.FalsifierLocusPackageAbsent,
					NegativeVerification: &domain.NegativeVerification{
						Status: domain.NegativeVerified,
					},
				},
			},
			Verdict: &domain.VerdictResult{
				Verdict:      domain.VerdictNoExploitPathFound,
				Reason:       "mandatory exploit condition is proven false",
				ConditionIDs: []domain.ConditionID{"C-LOCUS"},
			},
		}

		r := TrackerRationale(c)
		if !strings.Contains(r, "Not Exploitable") {
			t.Fatalf("missing headline: %s", r)
		}
		if !strings.Contains(r, "CVE-2026-84445") ||
			!strings.Contains(r, "паника в xDS routing interceptor") {
			t.Fatalf("missing defect description: %s", r)
		}
		if !strings.Contains(r, "defect locus linked into build") &&
			!strings.Contains(r, "пакеты дефектного кода") {
			t.Fatalf("missing falsified condition cause: %s", r)
		}
		if !strings.Contains(r, "v1.82.2") {
			t.Fatalf("missing planned update: %s", r)
		}
		if strings.Contains(r, "Текст выше можно использовать в задаче трекера") {
			t.Fatalf("unexpected boilerplate tracker closing: %s", r)
		}
	})

	t.Run("not affected renders outside version range", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:     "CVE-2025-1111",
				Module: "example.com/lib",
			},
			Product: domain.ProductSnapshot{
				Repository: "my-service",
				Commit:     "abc1234",
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimFalse,
				ResolvedVersion: "v2.0.0",
			},
			Verdict: &domain.VerdictResult{
				Verdict: domain.VerdictNotAffected,
				Reason:  "resolved version outside affected range",
			},
		}

		r := TrackerRationale(c)
		if !strings.Contains(r, "Not Affected") ||
			!strings.Contains(r, "example.com/lib") ||
			!strings.Contains(r, "v2.0.0") ||
			!strings.Contains(r, "вне уязвимого диапазона") {
			t.Fatalf("unexpected rationale: %s", r)
		}
	})

	t.Run("exploitable renders update command", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-9999",
				Module:        "example.com/bad",
				FixedVersions: []string{"v1.1.0"},
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.0.0",
			},
			Verdict: &domain.VerdictResult{
				Verdict: domain.VerdictExploitable,
				Reason:  "all mandatory exploit conditions are satisfied",
			},
		}

		r := TrackerRationale(c)
		if !strings.Contains(r, "Exploitable") ||
			!strings.Contains(r, "go get example.com/bad@v1.1.0") {
			t.Fatalf("unexpected exploitable rationale: %s", r)
		}
	})
}

var wantRUH2 = []string{
	"## Результат: NO_EXPLOIT_PATH_FOUND",
	"## В чём уязвимость",
	"## Почему она применима / не применима к этому продукту",
	"## Что подтверждено",
	"## Что не удалось подтвердить",
	"## Оценка и приоритет",
	"## Рекомендация по исправлению",
	"## Использование AI",
	"## Ссылка на технический аудит",
}

var wantENH2 = []string{
	"## Result: NO_EXPLOIT_PATH_FOUND",
	"## Vulnerability overview",
	"## Why it applies / does not apply to this product",
	"## Confirmed facts",
	"## What could not be confirmed",
	"## Assessment and priority",
	"## Remediation recommendation",
	"## AI usage",
	"## Technical audit link",
}

func TestMarkdownHumanSectionOrder(t *testing.T) {
	c := sampleAuditCase()

	md := Markdown(c, "ru")
	if md != Markdown(c) {
		t.Fatal("Markdown(c) must default to Russian and equal Markdown(c, \"ru\")")
	}
	got := h2Headings(md)
	if len(got) != 9 {
		t.Fatalf("expected exactly nine H2 sections, got %d:\n%s", len(got), strings.Join(got, "\n"))
	}
	for i, want := range wantRUH2 {
		if got[i] != want {
			t.Fatalf("H2[%d] = %q, want %q", i, got[i], want)
		}
	}
	if !strings.HasPrefix(md, "# GO-2026-0001 — ") {
		t.Fatalf("unexpected H1:\n%s", md)
	}
	if !strings.Contains(md, "Полный машинный снимок кейса: [report.json](report.json)") {
		t.Fatalf("missing report.json link:\n%s", md)
	}
	if !strings.Contains(md, "[Технический аудит](report.audit.md)") {
		t.Fatalf("missing audit link:\n%s", md)
	}

	en := Markdown(c, "en")
	gotEN := h2Headings(en)
	if len(gotEN) != 9 {
		t.Fatalf("expected exactly nine EN H2 sections, got %d:\n%s", len(gotEN), strings.Join(gotEN, "\n"))
	}
	for i, want := range wantENH2 {
		if gotEN[i] != want {
			t.Fatalf("EN H2[%d] = %q, want %q", i, gotEN[i], want)
		}
	}
	if !strings.Contains(en, "[Technical audit](report.audit.en.md)") {
		t.Fatalf("EN report must link the EN audit file:\n%s", en)
	}
}

func TestAuditMarkdownSections(t *testing.T) {
	c := sampleAuditCase()
	aud := AuditMarkdown(c, "ru")

	if !strings.HasPrefix(aud, "# GO-2026-0001 — технический аудит") {
		t.Fatalf("unexpected audit H1:\n%s", aud)
	}
	sections := []string{
		"## Результат и внутренние параметры triage",
		"## Источники и методы проверки",
		"## Применимость",
		"## Сопоставление с govulncheck",
		"## Первопричина, модель эксплуатации и локусы",
		"## Условия эксплуатации и верификация",
		"## Реестр доказательств",
		"## Факты сетевой экспозиции",
		"## Потоки данных",
		"## Покрытие входов и дефектных операций",
		"## Журнал инструментов",
		"## Факты среды",
		"## Сборка и тесты",
		"## Рецензирование",
		"## Рабочие гипотезы",
		"## Артефакты AI-анализа",
		"## Внутренние машинные гипотезы",
		"## Внутренние профили периметра",
		"## Полный список ограничений",
	}
	for _, s := range sections {
		if !strings.Contains(aud, s) {
			t.Fatalf("audit missing section %q:\n%s", s, aud)
		}
	}
	// Full fidelity spot checks.
	for _, want := range []string{
		"`CLM-1`", "locus-eval", "locus-package-absent", "EV-CLM-1",
		"ПОДТВЕРЖДЕНО", "package graph checked", "nv limitation",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"TX-001", "opaque dispatch", "boundary_arg", "constant input",
		"advisory-declared sink set", "machine-proposal", "machine-annotation",
		"enabler-candidate", "faulting site", "srchash", "arthash",
		"не изменяет финальный вердикт",
	} {
		if !strings.Contains(aud, want) {
			t.Fatalf("audit missing %q:\n%s", want, aud)
		}
	}
	// Limitations are deduplicated: "claim limitation" appears once in the list.
	if strings.Count(aud, "- claim limitation") != 1 {
		t.Fatalf("expected deduplicated limitation:\n%s", aud)
	}
	// Non-actual profile is explicitly marked hypothetical.
	if !strings.Contains(aud, "гипотетическая") {
		t.Fatalf("non-actual profile must be marked hypothetical:\n%s", aud)
	}
	en := AuditMarkdown(c, "en")
	if !strings.HasPrefix(en, "# GO-2026-0001 — technical audit") ||
		!strings.Contains(en, "hypothetical") {
		t.Fatalf("unexpected EN audit:\n%s", en)
	}
}

func TestReportTriageDecision(t *testing.T) {
	t.Run("exploitable unchanged keeps baseline without internal labels", func(t *testing.T) {
		c := minimalCase()
		md := Markdown(c, "ru")
		if !strings.Contains(md, "## Оценка и приоритет") {
			t.Fatalf("missing triage section:\n%s", md)
		}
		if !strings.Contains(md, "HIGH") || !strings.Contains(md, "7.5") {
			t.Fatalf("missing baseline severity:\n%s", md)
		}
		if !strings.Contains(md, "**P1**") {
			t.Fatalf("missing baseline/effective priority:\n%s", md)
		}
		if !strings.Contains(md, "без изменения") {
			t.Fatalf("missing UNCHANGED disposition wording:\n%s", md)
		}
		for _, banned := range []string{"ASSESSED", "PROVISIONAL", "NOT_APPLICABLE", "UNASSESSED", "Статус оценки", "SLA", "ContextualScore", "contextual"} {
			if strings.Contains(md, banned) {
				t.Fatalf("human report contains internal label %q:\n%s", banned, md)
			}
		}
		if strings.Contains(md, "Почему приоритет снижен") {
			t.Fatalf("no lowering happened — the lowering block must not appear:\n%s", md)
		}
	})

	t.Run("lowered disposition shows proven control", func(t *testing.T) {
		c := minimalCase()
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictExploitable}
		c.EvidenceGraph.Exposures = []domain.ExposureFact{
			{
				CallSite:  domain.CallSite{File: "main.go", Line: 10},
				Direction: "inbound",
				Kind:      "listener",
				Target:    "net.Listen",
				Address:   "127.0.0.1:9090",
				Scope:     domain.ScopeLoopback,
			},
		}
		md := Markdown(c, "ru")
		if c.ContextualRisk == nil || c.ContextualRisk.TriageDisposition != domain.TriageLowered {
			t.Fatalf("expected LOWERED disposition, got %+v", c.ContextualRisk)
		}
		if !strings.Contains(md, "приоритет снижен") {
			t.Fatalf("missing lowered wording:\n%s", md)
		}
		if !strings.Contains(md, "### Почему приоритет снижен") {
			t.Fatalf("missing lowering explanation block:\n%s", md)
		}
		if !strings.Contains(md, "loopback") {
			t.Fatalf("lowering must name the proven control:\n%s", md)
		}
	})

	t.Run("saturated downgrade is not presented as lowered", func(t *testing.T) {
		c := minimalCase()
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictExploitable}
		c.Vulnerability.BaseSeverity = "LOW"
		c.Vulnerability.BaseScore = 2.0
		c.EvidenceGraph.Exposures = []domain.ExposureFact{
			{
				CallSite:  domain.CallSite{File: "main.go", Line: 10},
				Direction: "inbound",
				Kind:      "listener",
				Target:    "net.Listen",
				Address:   "127.0.0.1:9090",
				Scope:     domain.ScopeLoopback,
			},
		}
		md := Markdown(c, "ru")
		if c.ContextualRisk == nil || c.ContextualRisk.Priority != domain.PriorityP3 {
			t.Fatalf("expected priority saturated at P3, got %+v", c.ContextualRisk)
		}
		if c.ContextualRisk.TriageDisposition == domain.TriageLowered {
			t.Fatalf("saturated downgrade must not claim LOWERED disposition")
		}
		if strings.Contains(md, "Почему приоритет снижен") {
			t.Fatalf("saturated downgrade must not show the lowering block:\n%s", md)
		}
	})

	t.Run("dismissed finding can be closed", func(t *testing.T) {
		c := minimalCase()
		c.Verdict = &domain.VerdictResult{
			Verdict: domain.VerdictNotAffected,
			Reason:  "resolved version outside affected range",
		}
		c.Affected.VersionAffected = domain.ClaimFalse
		md := Markdown(c, "ru")
		if !strings.Contains(md, "finding можно закрыть") {
			t.Fatalf("missing close wording:\n%s", md)
		}
		en := Markdown(c, "en")
		if !strings.Contains(en, "finding can be closed") {
			t.Fatalf("missing EN close wording:\n%s", en)
		}
	})

	t.Run("inconclusive keeps baseline priority", func(t *testing.T) {
		c := minimalCase()
		c.Verdict = &domain.VerdictResult{
			Verdict: domain.VerdictInconclusive,
			Reason:  "one or more mandatory exploit conditions remain unresolved: C-REACH",
		}
		md := Markdown(c, "ru")
		if !strings.Contains(md, "требуется дополнительная проверка; исходный приоритет сохранён") {
			t.Fatalf("missing inconclusive wording:\n%s", md)
		}
		if !strings.Contains(md, "**P1**") {
			t.Fatalf("inconclusive must retain baseline priority:\n%s", md)
		}
	})
}

func TestHumanReportNoContradictions(t *testing.T) {
	t.Run("exploitable never carries dismissal proposals", func(t *testing.T) {
		c := minimalCase()
		md := Markdown(c, "ru")
		for _, banned := range []string{"МОЖНО ОТКЛОНИТЬ", "DISMISSIBLE", "Предлагаемая оценка"} {
			if strings.Contains(md, banned) {
				t.Fatalf("EXPLOITABLE report contains %q:\n%s", banned, md)
			}
		}
	})
	t.Run("not affected never demands urgent fix", func(t *testing.T) {
		c := minimalCase()
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictNotAffected}
		c.Affected.PackagePresent = domain.ClaimFalse
		md := Markdown(c, "ru")
		for _, banned := range []string{"требуется первоочередное исправление", "немедленное устранение", "Требуется исправление"} {
			if strings.Contains(md, banned) {
				t.Fatalf("NOT_AFFECTED report contains %q:\n%s", banned, md)
			}
		}
		if !strings.Contains(md, "Срочного исправления не требуется") {
			t.Fatalf("missing no-urgent-fix statement:\n%s", md)
		}
	})
}

func TestHumanReportContainsNoAuditInternals(t *testing.T) {
	c := sampleAuditCase()
	md := Markdown(c, "ru")
	idRe := regexp.MustCompile(`\b(C|EV|TX|REV)-[A-Za-z0-9]+|\bH-\d+`)
	if m := idRe.FindString(md); m != "" {
		t.Fatalf("human report leaked internal id %q:\n%s", m, md)
	}
	for _, banned := range []string{
		"Evidence Register", "Tool Executions", "SinkClosure", "IngressClosure",
		"NegativeVerification", "PayloadUnproven", "ContextualScore",
		"ASSESSED", "PROVISIONAL", "SLA", "Producer:", "FalsifierBasis",
	} {
		if strings.Contains(md, banned) {
			t.Fatalf("human report contains audit internal %q:\n%s", banned, md)
		}
	}
	en := Markdown(c, "en")
	if m := idRe.FindString(en); m != "" {
		t.Fatalf("EN human report leaked internal id %q:\n%s", m, en)
	}
}

func TestAIUsageSection(t *testing.T) {
	t.Run("not used states it explicitly", func(t *testing.T) {
		c := minimalCase()
		md := Markdown(c, "ru")
		if !strings.Contains(md, "LLM-анализ в данном запуске не выполнялся.") {
			t.Fatalf("missing not-used statement:\n%s", md)
		}
		if !strings.Contains(md, "детерминированных проверках") {
			t.Fatalf("missing deterministic basis note:\n%s", md)
		}
		en := Markdown(c, "en")
		if !strings.Contains(en, "No LLM analysis was performed in this run.") {
			t.Fatalf("missing EN not-used statement:\n%s", en)
		}
	})
	t.Run("profile and justification alone do not count as LLM use", func(t *testing.T) {
		c := minimalCase()
		c.CVEAnalysisProfile = "llm-assisted"
		c.Justification = &domain.AnalysisJustification{Verdict: domain.VerdictExploitable}
		md := Markdown(c, "ru")
		if !strings.Contains(md, "LLM-анализ в данном запуске не выполнялся.") {
			t.Fatalf("profile/justification must not flip the used flag:\n%s", md)
		}
	})
	t.Run("counter without artifacts says attribution is unknown", func(t *testing.T) {
		c := minimalCase()
		c.Workflow.Usage.LLMCalls = 2
		md := Markdown(c, "ru")
		if strings.Contains(md, "не выполнялся") {
			t.Fatalf("recorded LLM calls must flip the used flag:\n%s", md)
		}
		if !strings.Contains(md, "привязанные артефакты анализа в кейсе не сохранены") {
			t.Fatalf("missing missing-attribution statement:\n%s", md)
		}
	})
	t.Run("used run lists outcomes and the disclaimer", func(t *testing.T) {
		c := minimalCase()
		c.CVEAnalysis = &domain.CVEAnalysisProposal{
			ID:         "A-1",
			Confidence: "HIGH",
			Mechanisms: []domain.DefectMechanism{{ID: "M-1", Summary: "bounds check missing"}},
		}
		c.SemanticReview = &domain.SemanticReview{Passed: true, Reviewer: "llm"}
		md := Markdown(c, "ru")
		for _, want := range []string{
			"Что делала LLM",
			"Что предложила LLM",
			"Что подтвердил или опроверг код по предложениям LLM",
			"Что из предложенного LLM принято в модель",
			"Мнение LLM и несостоявшиеся результаты",
			"bounds check missing",
			"LLM-выводы — это гипотезы",
		} {
			if !strings.Contains(md, want) {
				t.Fatalf("AI section missing %q:\n%s", want, md)
			}
		}
	})
}

func TestAIUsageProposalOutcomes(t *testing.T) {
	c := minimalCase()
	c.Workflow.Usage.LLMCalls = 4
	c.CVEAnalysis = &domain.CVEAnalysisProposal{
		ID:       "PROP-1",
		Revision: 1,
		Mechanisms: []domain.DefectMechanism{{
			ID: "M-1", Summary: "recursive parse without depth limit",
			FaultingSites:  []string{"example.com/mod/vulnpkg Parse"},
			AuxiliarySites: []string{"example.com/mod/vulnpkg Helper"},
		}},
	}
	subj := domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "Parse"}
	aux := domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "Helper"}
	c.ProposalVerifications = []domain.ProposalVerification{
		{Proposal: domain.ProposalRef{Source: domain.ProposalSourceCVEResearch, ID: "PROP-1", Revision: 1, MechanismID: "M-1"},
			Subject: &subj, Assertion: domain.AssertionFaultingSite, Check: domain.CheckSymbolExists, Result: domain.ClaimTrue},
		{Proposal: domain.ProposalRef{Source: domain.ProposalSourceCVEResearch, ID: "PROP-1", Revision: 1, MechanismID: "M-1"},
			Subject: &aux, Assertion: domain.AssertionAuxiliarySite, Check: domain.CheckSymbolExists, Result: domain.ClaimFalse},
		{Proposal: domain.ProposalRef{Source: domain.ProposalSourceCVEResearch, ID: "PROP-1", Revision: 1, MechanismID: "M-1"},
			Subject: &aux, Assertion: domain.AssertionAuxiliarySite, Check: domain.CheckSiteRole, Result: domain.ClaimUnknown,
			Detail: "semantic role requires manual review"},
	}
	// LLM root-cause candidate adopted into the model via typed provenance.
	c.RootCause = &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: "example.com/mod/vulnpkg", Symbol: "Parse", Role: domain.RootCauseSink,
			Mechanism: "llm-proposed: recursive parse",
			Proposal:  &domain.ProposalRef{Source: domain.ProposalSourceRootCause, ID: "RC-1", Revision: 1},
		}},
	}
	md := Markdown(c, "ru")
	if !strings.Contains(md, "объявления функций найдены в исходниках зависимости") ||
		!strings.Contains(md, "`example.com/mod/vulnpkg.Parse`") {
		t.Fatalf("existence-true assertion not shown:\n%s", md)
	}
	if !strings.Contains(md, "объявления не найдены или не разрешены по исходникам") ||
		!strings.Contains(md, "`example.com/mod/vulnpkg.Helper`") {
		t.Fatalf("existence-false assertion not shown:\n%s", md)
	}
	if !strings.Contains(md, "семантическая роль") || !strings.Contains(md, "не проверена автоматически") {
		t.Fatalf("unchecked semantic role not shown:\n%s", md)
	}
	if !strings.Contains(md, "кандидат `example.com/mod/vulnpkg.Parse` принят в модель") {
		t.Fatalf("typed adoption not shown:\n%s", md)
	}
	// A materialised record must never yield an unconditional "none".
	if strings.Contains(md, "результаты проверки предложений не сохранены") {
		t.Fatalf("materialised records misreported as absent:\n%s", md)
	}
	// The persisted English Detail must not leak into the Russian report.
	if strings.Contains(md, "semantic role requires manual review") {
		t.Fatalf("raw English Detail leaked into RU report:\n%s", md)
	}
	en := Markdown(c, "en")
	if !strings.Contains(en, "function declarations found in the dependency source") ||
		!strings.Contains(en, "semantic role") {
		t.Fatalf("EN disposition wording missing:\n%s", en)
	}

	// Legacy case without attribution records: the section must say so, not
	// invent outcomes.
	legacy := minimalCase()
	legacy.Workflow.Usage.LLMCalls = 2
	legacy.CVEAnalysis = &domain.CVEAnalysisProposal{ID: "P", Mechanisms: []domain.DefectMechanism{{ID: "M-1", Summary: "x"}}}
	lm := Markdown(legacy, "ru")
	if !strings.Contains(lm, "результаты проверки предложений не сохранены") {
		t.Fatalf("legacy case must state attribution is absent:\n%s", lm)
	}
}

func TestHypotheticalDeploymentNotAVerdict(t *testing.T) {
	c := minimalCase()
	c.Profiles = []domain.ProfileVerdict{
		{Profile: domain.ProfileZeroTrust, Verdict: domain.VerdictExploitable, Priority: domain.PriorityP1, IsTargetActual: true},
		{Profile: domain.ProfileClusterPerimeter, Verdict: domain.VerdictNoExploitPathFound, Priority: domain.PriorityDismissed, IsTargetActual: false},
	}
	md := Markdown(c, "ru")
	if strings.Contains(md, "NO_EXPLOIT_PATH_FOUND") || strings.Contains(md, "DISMISSED") {
		t.Fatalf("hypothetical environment verdict leaked into human report:\n%s", md)
	}
	if strings.Contains(md, "Действий не требуется") {
		t.Fatalf("human report must not promise no-action for hypothetical envs:\n%s", md)
	}
	if !strings.Contains(md, "### Что может изменить оценку") {
		t.Fatalf("missing scenario table block:\n%s", md)
	}
	if !strings.Contains(md, "Внутренний кластер") {
		t.Fatalf("scenario table must list the internal-cluster row:\n%s", md)
	}
	aud := AuditMarkdown(c, "ru")
	if !strings.Contains(aud, "гипотетическая") || !strings.Contains(aud, "NO_EXPLOIT_PATH_FOUND") {
		t.Fatalf("audit must carry both profiles with the hypothetical marker:\n%s", aud)
	}
}

func TestDeploymentGroundBasis(t *testing.T) {
	mk := func(basis string) *domain.AnalysisCase {
		c := minimalCase()
		c.Verdict = &domain.VerdictResult{
			Verdict:     domain.VerdictNoExploitPathFound,
			Reason:      "mandatory exploit condition is proven false",
			GroundBasis: basis,
		}
		return c
	}
	t.Run("declared trust is an accepted assumption", func(t *testing.T) {
		md := Markdown(mk(domain.BasisDeclaredTrust), "ru")
		if !strings.Contains(md, "заявленная граница доверия") ||
			!strings.Contains(md, "не проверка кода") {
			t.Fatalf("declared-trust basis must read as an assumption:\n%s", md)
		}
	})
	t.Run("auto perimeter is bounded by discovered manifests", func(t *testing.T) {
		md := Markdown(mk(domain.BasisAutoPerimeter), "ru")
		if !strings.Contains(md, "автоматически определённый кластерный периметр") {
			t.Fatalf("auto-perimeter basis missing:\n%s", md)
		}
	})
	t.Run("config origin is proven data provenance", func(t *testing.T) {
		md := Markdown(mk(domain.BasisConfigOrigin), "ru")
		if !strings.Contains(md, "локальные файлы конфигурации") {
			t.Fatalf("config-origin basis missing:\n%s", md)
		}
	})
	t.Run("code-level verdict prints no deployment basis", func(t *testing.T) {
		md := Markdown(mk(""), "ru")
		if strings.Contains(md, "Основание вердикта:") {
			t.Fatalf("unexpected basis paragraph for code-level verdict:\n%s", md)
		}
	})
}

func TestVulnerabilityEssenceNoInventedImpact(t *testing.T) {
	t.Run("recorded mechanism is used, no invented impact", func(t *testing.T) {
		c := minimalCase()
		md := Markdown(c, "ru")
		if !strings.Contains(md, "## В чём уязвимость") {
			t.Fatalf("missing essence section:\n%s", md)
		}
		if !strings.Contains(md, "out-of-bounds read") {
			t.Fatalf("resolved mechanism missing:\n%s", md)
		}
		for _, banned := range []string{"panic", "аварийн", "отказ в обслуживании", "RCE", "Remote Code Execution", "утечк"} {
			if strings.Contains(md, banned) {
				t.Fatalf("invented impact %q must not appear:\n%s", banned, md)
			}
		}
	})
	t.Run("unknown mechanism is explicit, not invented", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{ID: "GO-EMPTY"},
			Verdict:       &domain.VerdictResult{Verdict: domain.VerdictInconclusive},
		}
		md := Markdown(c, "ru")
		if !strings.Contains(md, "Механизм уязвимости не установлен") {
			t.Fatalf("missing explicit unknown mechanism:\n%s", md)
		}
		if !strings.HasPrefix(md, "# GO-EMPTY — механизм уязвимости не установлен") {
			t.Fatalf("H1 must say the mechanism is not established:\n%s", md)
		}
		en := Markdown(c, "en")
		if !strings.Contains(en, "Vulnerability mechanism not established") {
			t.Fatalf("missing EN unknown mechanism:\n%s", en)
		}
	})
	t.Run("advisory prose is marked as a source quote", func(t *testing.T) {
		c := minimalCase()
		c.RootCause = nil
		md := Markdown(c, "ru")
		if !strings.Contains(md, "По данным advisory: parsing defect in ModParse") {
			t.Fatalf("advisory-sourced description must be marked:\n%s", md)
		}
	})
	t.Run("entrypoint is never presented as the defect operation", func(t *testing.T) {
		c := minimalCase()
		c.RootCause = &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{
				{Package: "main", Symbol: "main", Role: domain.RootCauseEntrypoint, Mechanism: "advisory-listed affected symbol"},
			},
		}
		md := Markdown(c, "ru")
		if strings.Contains(md, "main.main`") {
			t.Fatalf("entrypoint must not be promoted to defect sink:\n%s", md)
		}
	})
}

func TestProductExploitPathEvidenceBounded(t *testing.T) {
	t.Run("exploitable without flows never claims a confirmed chain", func(t *testing.T) {
		c := minimalCase()
		md := Markdown(c, "ru")
		if !strings.Contains(md, "Сквозная подтверждённая цепочка от внешнего ввода к дефектной операции не построена") {
			t.Fatalf("missing honest no-chain statement:\n%s", md)
		}
		if strings.Contains(md, "Подтверждённая цепочка") {
			t.Fatalf("empty evidence must not produce a confirmed chain:\n%s", md)
		}
	})
	t.Run("unproven payload flow is named unproven", func(t *testing.T) {
		c := minimalCase()
		c.EvidenceGraph.DataFlows = []domain.DataFlow{
			{
				Source:          domain.CallSite{Function: "ReadAll"},
				Sink:            domain.CallSite{Function: "Parse"},
				Origin:          domain.OriginUnknown,
				PayloadUnproven: true,
			},
		}
		md := Markdown(c, "ru")
		if !strings.Contains(md, "аргументу 0") || !strings.Contains(md, "внешнее происхождение не доказано") {
			t.Fatalf("unproven flow must be labelled at its recorded scope:\n%s", md)
		}
		if strings.Contains(md, "Подтверждённая цепочка") {
			t.Fatalf("unproven flow must not be counted as confirmed:\n%s", md)
		}
	})
	t.Run("call path proves reachability, not the whole flow", func(t *testing.T) {
		c := minimalCase()
		c.EvidenceGraph.CallPaths = []domain.CallPath{
			{Frames: []domain.CallSite{
				{Package: "main", Function: "main"},
				{Package: "example.com/mod/vulnpkg", Function: "Parse"},
			}},
		}
		md := Markdown(c, "ru")
		if !strings.Contains(md, "достижимость") || !strings.Contains(md, "не всю цепочку передачи внешних данных") {
			t.Fatalf("call path limits must be stated:\n%s", md)
		}
	})
	t.Run("missing-call defect is a verified omission, not a call path", func(t *testing.T) {
		c := minimalCase()
		c.Exploit = &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{ID: "C-MISSING", Kind: domain.ConditionMissingCall, Mandatory: true, Description: "security check present"},
			},
		}
		c.Claims = []domain.Claim{
			{ConditionID: "C-MISSING", Result: domain.ClaimTrue},
		}
		md := Markdown(c, "ru")
		if !strings.Contains(md, "пропущенная обязательная проверка") {
			t.Fatalf("missing-call defect must be explained as an omission:\n%s", md)
		}
	})
}

func TestConfirmedFactsPreserveUnknowns(t *testing.T) {
	c := minimalCase()
	c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictInconclusive}
	c.Exploit = &domain.ExploitModel{
		MandatoryConditions: []domain.Condition{
			{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true, Description: "symbol reachable"},
			{ID: "C-PEER-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true, Description: "peer input controlled"},
		},
	}
	c.Claims = []domain.Claim{
		{ConditionID: "C-REACH", Result: domain.ClaimTrue},
		{ConditionID: "C-PEER-INPUT", Result: domain.ClaimUnknown},
	}
	md := Markdown(c, "ru")
	confirmed := md[strings.Index(md, "## Что подтверждено"):strings.Index(md, "## Что не удалось подтвердить")]
	if !strings.Contains(confirmed, "условие подтверждено") ||
		!strings.Contains(confirmed, "Достижимость символов") {
		t.Fatalf("confirmed TRUE condition missing:\n%s", confirmed)
	}
	if strings.Contains(confirmed, "Контроль ввода") {
		t.Fatalf("UNKNOWN condition must not appear as a confirmed fact:\n%s", confirmed)
	}
	if strings.Contains(confirmed, "все обязательные условия эксплуатации подтверждены") {
		t.Fatalf("partial confirmation must not read as all-confirmed:\n%s", confirmed)
	}
	unknowns := md[strings.Index(md, "## Что не удалось подтвердить"):strings.Index(md, "## Оценка и приоритет")]
	if !strings.Contains(unknowns, "Контроль ввода") || !strings.Contains(unknowns, "не разрешено") {
		t.Fatalf("UNKNOWN condition must be listed as unconfirmed:\n%s", unknowns)
	}
}

func TestSeverityProvenance(t *testing.T) {
	c := minimalCase()
	c.Vulnerability.SeveritySource = "NVD"
	c.Vulnerability.ScoreSource = "Vulners"
	md := Markdown(c, "ru")
	if !strings.Contains(md, "NVD / Vulners") {
		t.Fatalf("severity/score provenance missing:\n%s", md)
	}
	en := Markdown(c, "en")
	if !strings.Contains(en, "NVD / Vulners") {
		t.Fatalf("EN provenance missing:\n%s", en)
	}
	// A severity/score without an advisory source is not advisory-supplied:
	// the report must show «не указана» and attribute the synthesized
	// baseline to the analyzer default, never to the advisory.
	c2 := minimalCase()
	c2.Vulnerability.SeveritySource = ""
	c2.Vulnerability.ScoreSource = ""
	md2 := Markdown(c2, "ru")
	if !strings.Contains(md2, "не указана") || !strings.Contains(md2, "умолчание анализатора") {
		t.Fatalf("missing not-supplied/analyzer-default label:\n%s", md2)
	}
	if strings.Contains(md2, "OSV") {
		t.Fatalf("unsourced baseline must not carry the OSV label:\n%s", md2)
	}
	aud := AuditMarkdown(c, "ru")
	if !strings.Contains(aud, "severity_source") || !strings.Contains(aud, "NVD") {
		t.Fatalf("audit must carry raw provenance fields:\n%s", aud)
	}
}

func TestAuditClaimsKeepDemotionHistory(t *testing.T) {
	c := minimalCase()
	c.Claims = []domain.Claim{
		{
			ID:          "CLM-9",
			ConditionID: "C-PEER-INPUT",
			Result:      domain.ClaimUnknown,
			Falsifier:   domain.FalsifierGuards,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Notes:  "guards cover the sink",
			},
		},
	}
	aud := AuditMarkdown(c, "ru")
	if !strings.Contains(aud, "ПОДТВЕРЖДЕНО") || !strings.Contains(aud, "(демотировано)") {
		t.Fatalf("demoted verification history must be kept:\n%s", aud)
	}
	if !strings.Contains(aud, "guards cover the sink") {
		t.Fatalf("NV notes missing:\n%s", aud)
	}
	human := Markdown(c, "ru")
	if strings.Contains(human, "демотировано") {
		t.Fatalf("demotion internals must not reach the human report:\n%s", human)
	}
}

func TestAuditClosureInventories(t *testing.T) {
	c := sampleAuditCase()
	aud := AuditMarkdown(c, "ru")
	for _, want := range []string{
		"Покрытие входов и дефектных операций",
		"C-PEER-INPUT", "opaque dispatch", "boundary_arg",
		"advisory-declared sink set", "constant input",
		"example.com/mod/vulnpkg.Parse",
	} {
		if !strings.Contains(aud, want) {
			t.Fatalf("audit closures missing %q:\n%s", want, aud)
		}
	}
}

func TestReportLegacyRiskNormalization(t *testing.T) {
	t.Run("stale risk record is re-assessed", func(t *testing.T) {
		c := minimalCase()
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictInconclusive}
		c.ContextualRisk = &domain.ContextualRisk{
			Status:          domain.RiskStatusAssessed,
			ContextualLevel: domain.RiskLevelCritical,
			Priority:        domain.PriorityP0,
			Factors:         domain.RiskFactors{Verdict: "EXPLOITABLE"},
		}
		md := Markdown(c, "ru")
		if c.ContextualRisk.TriageDisposition != domain.TriageInconclusive {
			t.Fatalf("expected INCONCLUSIVE disposition, got %+v", c.ContextualRisk)
		}
		if c.ContextualRisk.BasePriority != domain.PriorityP1 || c.ContextualRisk.Priority != domain.PriorityP1 {
			t.Fatalf("inconclusive must keep baseline P1, got %+v", c.ContextualRisk)
		}
		if !strings.Contains(md, "исходный приоритет сохранён") {
			t.Fatalf("normalized disposition missing from output:\n%s", md)
		}
	})
	t.Run("fresh record is not recomputed", func(t *testing.T) {
		c := minimalCase()
		md := Markdown(c, "ru")
		_ = md
		if c.ContextualRisk == nil || c.ContextualRisk.Factors.Verdict != string(domain.VerdictExploitable) {
			t.Fatalf("expected assessment persisted, got %+v", c.ContextualRisk)
		}
		prio := c.ContextualRisk.Priority
		Markdown(c, "ru")
		if c.ContextualRisk.Priority != prio {
			t.Fatal("ensureTriageAssessment must be idempotent for fresh records")
		}
	})
	t.Run("nil verdict never invents one", func(t *testing.T) {
		c := &domain.AnalysisCase{Vulnerability: domain.Vulnerability{ID: "GO-NIL"}}
		md := Markdown(c, "ru")
		if c.ContextualRisk != nil {
			t.Fatal("no verdict — no triage assessment may be invented")
		}
		if !strings.Contains(md, "вердикт не вынесен") {
			t.Fatalf("missing not-available statement:\n%s", md)
		}
	})
}

func TestReportMarkdownDeterministic(t *testing.T) {
	mk := func() *domain.AnalysisCase { return sampleAuditCase() }
	c := mk()
	first := Markdown(c, "ru")
	if first != Markdown(c, "ru") {
		t.Fatal("Markdown must be deterministic across calls")
	}
	if first != Markdown(mk(), "ru") {
		t.Fatal("Markdown must be deterministic across identical cases")
	}
	en := Markdown(c, "en")
	if en != Markdown(c, "en") {
		t.Fatal("EN Markdown must be deterministic")
	}
	aud := AuditMarkdown(c, "ru")
	if aud != AuditMarkdown(mk(), "ru") {
		t.Fatal("AuditMarkdown must be deterministic")
	}
}

func TestReportTicketMetadata(t *testing.T) {
	c := &domain.AnalysisCase{
		ID:              "CASE-1234",
		TicketID:        "JIRA-538506",
		TicketComponent: "GATEWAY",
		TicketRelease:   "2.6.0-release",
		Vulnerability: domain.Vulnerability{
			ID: "GO-2026-4950",
		},
		Product: domain.ProductSnapshot{
			Repository: "/path/to/repo",
			Commit:     "abcdef",
			GoVersion:  "go1.26.1",
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
	}

	mdRU := Markdown(c, "ru")
	if !strings.Contains(mdRU, "- Тикет: `JIRA-538506`") {
		t.Errorf("RU markdown missing ticket ID, got:\n%s", mdRU)
	}
	if !strings.Contains(mdRU, "- Компонент: `GATEWAY`") {
		t.Errorf("RU markdown missing ticket component, got:\n%s", mdRU)
	}
	if !strings.Contains(mdRU, "- Релиз: `2.6.0-release`") {
		t.Errorf("RU markdown missing ticket release, got:\n%s", mdRU)
	}

	mdEN := Markdown(c, "en")
	if !strings.Contains(mdEN, "- Ticket: `JIRA-538506`") {
		t.Errorf("EN markdown missing ticket ID, got:\n%s", mdEN)
	}
	if !strings.Contains(mdEN, "- Component: `GATEWAY`") {
		t.Errorf("EN markdown missing ticket component, got:\n%s", mdEN)
	}
	if !strings.Contains(mdEN, "- Release: `2.6.0-release`") {
		t.Errorf("EN markdown missing ticket release, got:\n%s", mdEN)
	}
}

func TestWriteGeneratesSevenFiles(t *testing.T) {
	c := sampleAuditCase()
	tmpDir := t.TempDir()
	if err := Write(tmpDir, c); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	want := []string{
		"report.json", "openvex.json", "cyclonedx.json",
		"report.md", "report.en.md",
		"report.audit.md", "report.audit.en.md",
	}
	for _, name := range want {
		fi, err := os.Stat(filepath.Join(tmpDir, name))
		if err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
		if fi.Size() == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
	ru, err := os.ReadFile(filepath.Join(tmpDir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ru), "## Результат:") {
		t.Fatalf("report.md is not the human RU report:\n%s", ru)
	}
	aud, err := os.ReadFile(filepath.Join(tmpDir, "report.audit.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(aud), "технический аудит") {
		t.Fatalf("report.audit.md is not the audit document:\n%s", aud)
	}
}

func TestMarkdownLocalizationRU(t *testing.T) {
	c := sampleAuditCase()

	md := Markdown(c, "ru")
	expectedPhrases := []string{
		"- Кейс: `case-min`",
		"## Результат: NO_EXPLOIT_PATH_FOUND",
		"Уязвимый путь исполнения отсутствует",
		"## В чём уязвимость",
		"## Что подтверждено",
		"## Что не удалось подтвердить",
		"## Оценка и приоритет",
		"## Рекомендация по исправлению",
		"## Использование AI",
		"## Ссылка на технический аудит",
		"Обновите зависимость `example.com/mod` с `v1.1.0` до `v1.2.0`",
	}
	for _, phrase := range expectedPhrases {
		if !strings.Contains(md, phrase) {
			t.Errorf("RU markdown missing %q:\n%s", phrase, md)
		}
	}
}

func TestMarkdownLocalizationEN(t *testing.T) {
	c := sampleAuditCase()

	md := Markdown(c, "en")
	expectedPhrases := []string{
		"- Case: `case-min`",
		"## Result: NO_EXPLOIT_PATH_FOUND",
		"No exploit path exists",
		"## Vulnerability overview",
		"## Confirmed facts",
		"## What could not be confirmed",
		"## Assessment and priority",
		"## Remediation recommendation",
		"## AI usage",
		"## Technical audit link",
		"Update `example.com/mod` from `v1.1.0` to `v1.2.0`",
	}
	for _, phrase := range expectedPhrases {
		if !strings.Contains(md, phrase) {
			t.Errorf("EN markdown missing %q:\n%s", phrase, md)
		}
	}
}

func TestReportRussianLocalizationNoEnglishLeaks(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-russian-localization",
		Vulnerability: domain.Vulnerability{
			ID:            "GO-2022-0603",
			Module:        "gopkg.in/yaml.v3",
			FixedVersions: []string{"v3.0.0-20220521103104-8f96da9f5d5e"},
		},
		Product: domain.ProductSnapshot{
			Repository: "my-service",
			Commit:     "1070baac73db",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
			Reason:  "all mandatory exploit conditions are satisfied",
		},
		DetectedPerimeter:  domain.PerimeterPublic,
		PerimeterRationale: "public exposure detected: inbound listener :8080",
		Profiles: []domain.ProfileVerdict{
			{
				Profile:        domain.ProfileZeroTrust,
				Verdict:        domain.VerdictExploitable,
				Priority:       domain.PriorityP0,
				IsTargetActual: true,
			},
			{
				Profile:        domain.ProfileClusterPerimeter,
				Verdict:        domain.VerdictNoExploitPathFound,
				Priority:       domain.PriorityDismissed,
				IsTargetActual: false,
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{
					Direction:     "inbound",
					Kind:          "listener",
					Target:        "net/http.ListenAndServe",
					Address:       ":8080",
					AddressSource: "literal",
					Scope:         "all-interfaces",
					CallSite:      domain.CallSite{File: "main.go", Line: 40},
				},
			},
		},
	}

	md := Markdown(c, "ru")
	if strings.Contains(md, "all mandatory exploit conditions are satisfied") {
		t.Errorf("found raw English verdict reason in Russian report:\n%s", md)
	}
	if !strings.Contains(md, "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)") {
		t.Errorf("missing localized Russian verdict reason in report:\n%s", md)
	}
	if strings.Contains(md, "Рекомендуемый SLA") || strings.Contains(md, "Recommended SLA") ||
		strings.Contains(md, "24h") || strings.Contains(md, "Sprint") {
		t.Errorf("found SLA internals in Russian report:\n%s", md)
	}

	aud := AuditMarkdown(c, "ru")
	if !strings.Contains(aud, "`Публичный (public)`") {
		t.Errorf("audit missing localized perimeter:\n%s", aud)
	}
	if !strings.Contains(aud, "Обнаружен публичный доступ: входящий слушатель :8080") {
		t.Errorf("audit missing localized perimeter rationale:\n%s", aud)
	}
	if !strings.Contains(aud, "все интерфейсы (0.0.0.0)") {
		t.Errorf("audit missing localized exposure scope:\n%s", aud)
	}
}

func TestAuditEvidenceRegister(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-evidence",
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2022-0603",
			Module: "gopkg.in/yaml.v3",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
			Reason:  "all mandatory exploit conditions are satisfied",
		},
		Claims: []domain.Claim{
			{
				ConditionID: "C-REACH",
				Result:      domain.ClaimTrue,
				EvidenceIDs: []domain.EvidenceID{"EV-006"},
				Explanation: "govulncheck produced call path(s) to the affected symbol(s)",
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				{
					ID:      "EV-006",
					Kind:    domain.EvidenceGovulncheck,
					Tool:    "govulncheck",
					Command: "govulncheck -json -mode source ./...",
					Content: "call path json",
				},
				{
					ID:        "EV-008",
					Kind:      domain.EvidenceSourceSnippet,
					File:      "main.go",
					StartLine: 42,
					Content:   "yaml.Unmarshal(body, &p)",
				},
			},
			CallPaths: []domain.CallPath{
				{
					EvidenceID: "EV-006",
					Frames: []domain.CallSite{
						{Function: "main.main", File: "main.go", Line: 20},
						{Function: "gopkg.in/yaml.v3.Unmarshal", File: "yaml.go", Line: 90},
					},
				},
			},
		},
	}

	aud := AuditMarkdown(c, "ru")
	if !strings.Contains(aud, "## Реестр доказательств") {
		t.Fatalf("expected evidence register in audit:\n%s", aud)
	}
	if !strings.Contains(aud, "| `EV-006` | Анализ вызовов (govulncheck) |") {
		t.Errorf("expected EV-006 in audit register:\n%s", aud)
	}
	if !strings.Contains(aud, "Трасса вызова (2 кадров): `main.main` → ... → `gopkg.in/yaml.v3.Unmarshal`") {
		t.Errorf("expected call path details for EV-006:\n%s", aud)
	}
	if !strings.Contains(aud, "yaml.Unmarshal(body, &p)") {
		t.Errorf("expected EV-008 snippet:\n%s", aud)
	}
	if !strings.Contains(aud, "Трасса вызовов govulncheck достигает уязвимых символов библиотеки") {
		t.Errorf("expected localized claim explanation in audit claims:\n%s", aud)
	}

	human := Markdown(c, "ru")
	if strings.Contains(human, "EV-006") || strings.Contains(human, "Реестр доказательств") {
		t.Errorf("human report must not carry the evidence register:\n%s", human)
	}
}

func TestGovulncheckComparisonAndDivergence(t *testing.T) {
	t.Run("audit explains divergence when scanner sees calls but verdict is NEPF", func(t *testing.T) {
		c := sampleAuditCase()
		aud := AuditMarkdown(c, "ru")
		if !strings.Contains(aud, "## Сопоставление с govulncheck") {
			t.Fatalf("missing govulncheck comparison:\n%s", aud)
		}
		if !strings.Contains(aud, "Уязвимый код вызывается") {
			t.Fatalf("expected reachable finding:\n%s", aud)
		}
		if !strings.Contains(aud, "NO_EXPLOIT_PATH_FOUND") {
			t.Fatalf("expected analyzer verdict in comparison:\n%s", aud)
		}
		if !strings.Contains(aud, "ложной тревогой") && !strings.Contains(aud, "false positive") {
			t.Fatalf("expected divergence rationale:\n%s", aud)
		}
	})
	t.Run("comparison absent without tool run or call paths", func(t *testing.T) {
		c := minimalCase()
		aud := AuditMarkdown(c, "ru")
		if strings.Contains(aud, "Сопоставление с govulncheck") {
			t.Fatalf("comparison must be skipped without govulncheck data:\n%s", aud)
		}
	})
	t.Run("clean scanner with exploitable verdict explains the divergence", func(t *testing.T) {
		c := minimalCase()
		c.EvidenceGraph.ToolExecutions = []domain.ToolExecution{
			{ID: "TX-1", Tool: "govulncheck", ExitCode: 0},
		}
		c.EvidenceGraph.Evidence = []domain.Evidence{
			{ID: "EV-MISSING-CALL", Kind: domain.EvidenceSourceSnippet, Content: "missing verify call"},
		}
		aud := AuditMarkdown(c, "ru")
		if !strings.Contains(aud, "Трасса вызовов не обнаружена") {
			t.Fatalf("expected clean scanner finding:\n%s", aud)
		}
		if !strings.Contains(aud, "пропуске обязательной проверки") {
			t.Fatalf("expected missing-call divergence rationale:\n%s", aud)
		}
	})
}

func TestFixCompatibility(t *testing.T) {
	tests := []struct {
		name      string
		resolved  string
		fixed     string
		wantDrop  bool
		wantMajor bool
		wantOK    bool
	}{
		{
			name:      "minor/patch same major is drop-in",
			resolved:  "v1.2.0",
			fixed:     "v1.2.4",
			wantDrop:  true,
			wantMajor: false,
			wantOK:    true,
		},
		{
			name:      "different major is major bump",
			resolved:  "v1.2.0",
			fixed:     "v2.0.1",
			wantDrop:  false,
			wantMajor: true,
			wantOK:    true,
		},
		{
			name:      "un-prefixed versions same major is drop-in",
			resolved:  "1.2.0",
			fixed:     "1.3.0",
			wantDrop:  true,
			wantMajor: false,
			wantOK:    true,
		},
		{
			name:      "empty resolved",
			resolved:  "",
			fixed:     "v1.2.4",
			wantDrop:  false,
			wantMajor: false,
			wantOK:    false,
		},
		{
			name:      "empty fixed",
			resolved:  "v1.2.0",
			fixed:     "",
			wantDrop:  false,
			wantMajor: false,
			wantOK:    false,
		},
		{
			name:      "invalid resolved",
			resolved:  "not-a-semver",
			fixed:     "v1.2.4",
			wantDrop:  false,
			wantMajor: false,
			wantOK:    false,
		},
		{
			name:      "invalid fixed",
			resolved:  "v1.2.0",
			fixed:     "not-a-semver",
			wantDrop:  false,
			wantMajor: false,
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDrop, gotMajor, gotOK := FixCompatibility(tt.resolved, tt.fixed)
			if gotDrop != tt.wantDrop || gotMajor != tt.wantMajor || gotOK != tt.wantOK {
				t.Fatalf("FixCompatibility(%q, %q) = (%v, %v, %v), want (%v, %v, %v)",
					tt.resolved, tt.fixed, gotDrop, gotMajor, gotOK, tt.wantDrop, tt.wantMajor, tt.wantOK)
			}
		})
	}
}

func TestRemediationSemVerCompatibility(t *testing.T) {
	t.Run("same-major fix renders drop-in notice in RU and EN", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-TEST1",
				Module:        "example.com/mod",
				FixedVersions: []string{"v1.2.4"},
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.2.0",
			},
		}

		ru := remediation(c, true)
		if !strings.Contains(ru, "(совместимо по SemVer: minor/patch, без изменения импортов)") {
			t.Fatalf("remediation RU missing drop-in notice:\n%s", ru)
		}

		en := remediation(c, false)
		if !strings.Contains(en, "(SemVer drop-in: minor/patch, no import path changes)") {
			t.Fatalf("remediation EN missing drop-in notice:\n%s", en)
		}

		if !c.Affected.UpgradeDropIn {
			t.Fatalf("expected UpgradeDropIn to be true, got %v", c.Affected.UpgradeDropIn)
		}
		if c.Affected.UpgradeMajorBump {
			t.Fatalf("expected UpgradeMajorBump to be false, got %v", c.Affected.UpgradeMajorBump)
		}
	})

	t.Run("different-major fix renders major bump notice in RU and EN", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-TEST2",
				Module:        "example.com/mod",
				FixedVersions: []string{"v2.0.1"},
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.2.0",
			},
		}

		ru := remediation(c, true)
		if !strings.Contains(ru, "(Внимание: смена мажорной версии v2, требуются обновление путей импорта и адаптация API)") {
			t.Fatalf("remediation RU missing major bump notice:\n%s", ru)
		}

		en := remediation(c, false)
		if !strings.Contains(en, "(Notice: major version bump to v2, import path changes and API adaptation required)") {
			t.Fatalf("remediation EN missing major bump notice:\n%s", en)
		}

		if c.Affected.UpgradeDropIn {
			t.Fatalf("expected UpgradeDropIn to be false, got %v", c.Affected.UpgradeDropIn)
		}
		if !c.Affected.UpgradeMajorBump {
			t.Fatalf("expected UpgradeMajorBump to be true, got %v", c.Affected.UpgradeMajorBump)
		}
	})

	t.Run("report.Write populates AffectedResult upgrade flags", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-TEST3",
				Module:        "example.com/mod",
				FixedVersions: []string{"v1.3.0"},
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.2.0",
			},
		}

		tmpDir := t.TempDir()
		if err := Write(tmpDir, c); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if !c.Affected.UpgradeDropIn {
			t.Fatalf("expected UpgradeDropIn to be true after Write")
		}

		repJSON, err := os.ReadFile(filepath.Join(tmpDir, "report.json"))
		if err != nil {
			t.Fatalf("reading report.json: %v", err)
		}
		if !strings.Contains(string(repJSON), `"upgrade_drop_in": true`) {
			t.Fatalf("report.json missing upgrade_drop_in flag: %s", string(repJSON))
		}
	})
}

func TestLocalizeVerdictReason(t *testing.T) {
	tests := []struct {
		input  string
		isRU   bool
		wanted string
	}{
		{
			input:  "all mandatory exploit conditions are satisfied",
			isRU:   true,
			wanted: "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)",
		},
		{
			input:  "all mandatory exploit conditions are satisfied",
			isRU:   false,
			wanted: "all mandatory exploit conditions are satisfied",
		},
		{
			input:  "all mandatory conditions met",
			isRU:   true,
			wanted: "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)",
		},
		{
			input:  "mandatory exploit condition is proven false",
			isRU:   true,
			wanted: "Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)",
		},
		{
			input:  "vulnerable module is not part of the product dependency graph",
			isRU:   true,
			wanted: "Уязвимый модуль не входит в граф зависимостей продукта",
		},
		{
			input:  "none of the affected module(s) example.com/pkg resolve to a product dependency (go list -m all)",
			isRU:   true,
			wanted: "Ни один из уязвимых модулей example.com/pkg не входит в зависимости продукта (go list -m all)",
		},
		{
			input:  "resolved dependency version is outside affected range",
			isRU:   true,
			wanted: "Разрешённая версия зависимости находится вне уязвимого диапазона",
		},
		{
			input:  "resolved version v2.0.0 is outside the affected range",
			isRU:   true,
			wanted: "Разрешённая версия v2.0.0 находится вне уязвимого диапазона",
		},
		{
			input:  "affected package is not imported by the product build",
			isRU:   true,
			wanted: "Уязвимый пакет не импортируется в сборке продукта",
		},
		{
			input:  "affected package(s) example.com/mod/pkg are absent from the product's transitive import closure (go list -deps -test ./...) — the code is not linked into the product",
			isRU:   true,
			wanted: "Уязвимый пакет(ы) example.com/mod/pkg отсутствует в транзитивном графе импортов сборки (go list -deps -test ./...) — код не скомпилирован в продукт",
		},
		{
			input:  "affected packages are constrained to other platforms/build configurations",
			isRU:   true,
			wanted: "Уязвимые пакеты ограничены другими платформами или конфигурациями сборки",
		},
		{
			input:  "one or more mandatory exploit conditions remain unresolved",
			isRU:   true,
			wanted: "Одно или несколько обязательных условий эксплуатации не подтверждены",
		},
		{
			input:  "one or more mandatory exploit conditions remain unresolved: C-REACH, C-PEER-INPUT",
			isRU:   true,
			wanted: "Одно или несколько обязательных условий эксплуатации не подтверждены: C-REACH, C-PEER-INPUT",
		},
		{
			input:  "all modeled mandatory conditions are satisfied, but 1 sink candidate(s) are unresolved or proven absent from the build (pkg.Symbol): the exploit model is pruned and cannot ground a positive verdict",
			isRU:   true,
			wanted: "Все смоделированные обязательные условия выполнены, но часть дефектных точек сбоя (sinks) не разрешена или отсутствует в сборке: модель усечена и не может обосновать положительный вердикт",
		},
		{
			input:  "cluster-perimeter verdict rests on a declared trust boundary, but 1 advisory-declared subject(s) are unresolved: an operator assertion cannot discharge an unmodeled exploit shape",
			isRU:   true,
			wanted: "Вердикт внутрикластерного периметра опирается на объявленную границу доверия, но часть заявленных в advisory функций не разрешена: утверждение оператора не может закрыть несмоделированный путь атаки",
		},
	}

	for _, tt := range tests {
		got := localizeVerdictReason(tt.input, tt.isRU)
		if got != tt.wanted {
			t.Errorf("localizeVerdictReason(%q, %v) =\n%q\nwant:\n%q", tt.input, tt.isRU, got, tt.wanted)
		}
	}
}

// absPathCase mirrors the review demo: an absolute checkout, one dependency
// in the module cache and a call/data-flow site recorded with host paths —
// the human/audit reports must render only attributed locations.
func absPathCase() *domain.AnalysisCase {
	c := minimalCase()
	c.Product.Repository = "/Users/dev/ws/demo"
	c.Vulnerability.Module = "gopkg.in/yaml.v2"
	c.EvidenceGraph = domain.EvidenceGraph{
		Evidence: []domain.Evidence{
			{ID: "EV-MOD-1", Kind: domain.EvidenceModuleGraph, Content: `{"Path":"example.com/demo","Main":true,"Dir":"/Users/dev/ws/demo"}
{"Path":"gopkg.in/yaml.v2","Version":"v2.2.2","Dir":"/Users/dev/go/pkg/mod/gopkg.in/yaml.v2@v2.2.2"}
`},
			{ID: "EV-FLOW-1", Kind: domain.EvidenceDataFlow, Source: "provenance", File: "/Users/dev/ws/demo/main.go", StartLine: 39, Content: "flow"},
		},
		ModuleUsages: []domain.CallSite{
			{File: "/Users/dev/ws/demo/main.go", Line: 39, Function: "main.load", Callee: "yaml.Unmarshal", ModuleOwner: "gopkg.in/yaml.v2"},
		},
		DataFlows: []domain.DataFlow{
			{
				ConditionID: "C-INPUT",
				Source:      domain.CallSite{File: "/Users/dev/ws/demo/main.go", Line: 30, Function: "main.load"},
				Sink:        domain.CallSite{File: "/Users/dev/ws/demo/main.go", Line: 39, Function: "main.load", Callee: "yaml.Unmarshal"},
				Arg:         0,
				Origin:      domain.OriginExternalUntrusted,
			},
		},
		CallPaths: []domain.CallPath{{
			ConditionID: "C-REACH",
			Frames: []domain.CallSite{
				{File: "/Users/dev/ws/demo/main.go", Line: 10, Function: "main", Package: "example.com/demo"},
				{File: "/Users/dev/go/pkg/mod/gopkg.in/yaml.v2@v2.2.2/decode.go", Line: 268, Function: "unmarshal", Package: "gopkg.in/yaml.v2"},
			},
		}},
	}
	c.Claims = []domain.Claim{{ID: "CL-1", ConditionID: "C-INPUT", Result: domain.ClaimTrue}}
	c.Exploit = &domain.ExploitModel{
		Class:               "RESOURCE_EXHAUSTION",
		Impact:              "denial of service",
		RootCauses:          []domain.SymbolRef{{Package: "gopkg.in/yaml.v2", Symbol: "decoder.unmarshal"}},
		MandatoryConditions: []domain.Condition{{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true}},
	}
	return c
}

func TestMarkdownNoHostPaths(t *testing.T) {
	c := absPathCase()
	for _, doc := range []string{Markdown(c, "ru"), Markdown(c, "en"), AuditMarkdown(c, "ru"), AuditMarkdown(c, "en")} {
		if strings.Contains(doc, "/Users/dev") {
			t.Fatalf("host checkout prefix leaked into report:\n%s", doc)
		}
		if strings.Contains(doc, "pkg/mod/gopkg.in") {
			t.Fatalf("module-cache path leaked into report:\n%s", doc)
		}
	}
	ru := Markdown(c, "ru")
	for _, want := range []string{
		"Репозиторий: `demo`",
		"`yaml.Unmarshal` (`main.go:39`)",
		"истощение ресурсов",
	} {
		if !strings.Contains(ru, want) {
			t.Fatalf("RU report missing %q:\n%s", want, ru)
		}
	}
	en := Markdown(c, "en")
	if !strings.Contains(en, "resource exhaustion") {
		t.Fatalf("EN report missing localized class label:\n%s", en)
	}
	aud := AuditMarkdown(c, "ru")
	for _, want := range []string{"main.go:39", "gopkg.in/yaml.v2@v2.2.2/decode.go:268", "EV-FLOW-1", "EV-MOD-1"} {
		if !strings.Contains(aud, want) {
			t.Fatalf("audit missing %q:\n%s", want, aud)
		}
	}
}

func TestSeverityNotSuppliedLabelsAnalyzerDefault(t *testing.T) {
	c := minimalCase()
	c.Vulnerability.BaseSeverity = "MEDIUM"
	c.Vulnerability.BaseScore = 5.0
	c.Vulnerability.SeveritySource = ""
	c.Vulnerability.ScoreSource = ""

	ru := Markdown(c, "ru")
	if strings.Contains(ru, "OSV") && strings.Contains(ru, "Источник оценки:** OSV") {
		t.Fatalf("analyzer-synthesized baseline presented as OSV:\n%s", ru)
	}
	if !strings.Contains(ru, "не указана") {
		t.Fatalf("RU report missing «не указана» severity:\n%s", ru)
	}
	if !strings.Contains(ru, "умолчание анализатора") {
		t.Fatalf("RU report missing analyzer-default source label:\n%s", ru)
	}
	en := Markdown(c, "en")
	if !strings.Contains(en, "not supplied") || !strings.Contains(en, "analyzer default") {
		t.Fatalf("EN report missing not-supplied/analyzer-default labels:\n%s", en)
	}
}

func TestConfirmedFactsPresenceGated(t *testing.T) {
	c := minimalCase()
	// No persisted presence check: advisory-listed functions only.
	ru := Markdown(c, "ru")
	if strings.Contains(ru, "точка дефекта локализована") {
		t.Fatalf("defect-site claim without persisted presence check:\n%s", ru)
	}
	if !strings.Contains(ru, "указанные в advisory уязвимые функции") {
		t.Fatalf("missing advisory-declared fallback:\n%s", ru)
	}
	// With a persisted symbol decl the localized-site wording is allowed.
	c.EvidenceGraph.SymbolDecls = map[string]*domain.CallSite{
		"example.com/mod/vulnpkg.Parse": {File: "parse.go", Line: 12},
	}
	ru = Markdown(c, "ru")
	if !strings.Contains(ru, "точка дефекта локализована") {
		t.Fatalf("presence check not honored:\n%s", ru)
	}
}

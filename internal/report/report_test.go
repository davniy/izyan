package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

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
}

func TestTrackerRationale(t *testing.T) {
	sym := func(pkg, s string) domain.SymbolRef {
		return domain.SymbolRef{Package: pkg, Symbol: s}
	}

	t.Run("no exploit path found renders complete tracker justification", func(t *testing.T) {
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
				GoVersion:  "1.23.0",
				GOOS:       "linux",
				GOARCH:     "amd64",
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.80.0",
			},
			Exploit: &domain.ExploitModel{
				LocusSubjects: []domain.SymbolRef{
					sym("google.golang.org/grpc/internal/xds", "RouteAndProcess"),
					sym("google.golang.org/grpc/internal/transport", "HandleStreams"),
				},
				NonLocusBasis: []domain.LocusDecision{
					{
						Symbol:    sym("google.golang.org/grpc/internal/transport", "HandleStreams"),
						Authority: "эксперт",
						Basis:     "вспомогательная диспетчеризация, дефектная операция отсутствует",
					},
				},
			},
			EvidenceGraph: domain.EvidenceGraph{
				Evidence: []domain.Evidence{
					{
						Kind:    domain.EvidencePackageList,
						Content: `{"ImportPath":"google.golang.org/grpc/internal/transport"}` + "\n" + `{"ImportPath":"example.com/demo-service"}`,
					},
				},
				Exposures: []domain.ExposureFact{
					{
						CallSite:  domain.CallSite{File: "components/service/consumer.go", Line: 53},
						Direction: "inbound",
						Kind:      "grpc_listener",
						Target:    "google.golang.org/grpc.NewServer",
					},
				},
			},
			Verdict: &domain.VerdictResult{
				Verdict: domain.VerdictNoExploitPathFound,
				Reason:  "mandatory exploit condition is proven false",
			},
		}

		r := TrackerRationale(c)

		// 1. Headline
		if !strings.Contains(r, "Not Exploitable (Уязвимость не эксплуатируется)") {
			t.Fatalf("missing headline: %s", r)
		}
		// 2. Library & Scanner
		if !strings.Contains(r, "google.golang.org/grpc v1.80.0") ||
			!strings.Contains(r, "False Positive") ||
			!strings.Contains(r, "demo-service") {
			t.Fatalf("missing library/scanner context: %s", r)
		}
		// 3. Commit & Snapshot
		if !strings.Contains(r, "74224f4d1234") ||
			!strings.Contains(r, "Go 1.23.0") ||
			!strings.Contains(r, "linux/amd64") {
			t.Fatalf("missing snapshot context: %s", r)
		}
		// 4. Vulnerability mechanism
		if !strings.Contains(r, "CVE-2026-84445") ||
			!strings.Contains(r, "паника в xDS routing interceptor") {
			t.Fatalf("missing defect description: %s", r)
		}
		// 5. Absent package
		if !strings.Contains(r, "google.golang.org/grpc/internal/xds") ||
			!strings.Contains(r, "отсутствуют и в бинарный файл не попадают") {
			t.Fatalf("missing absent packages info: %s", r)
		}
		// 6. Product exposures
		if !strings.Contains(r, "components/service/consumer.go:53") ||
			!strings.Contains(r, "google.golang.org/grpc.NewServer") {
			t.Fatalf("missing exposures info: %s", r)
		}
		// 7. Present package symbols
		if !strings.Contains(r, "HandleStreams") ||
			!strings.Contains(r, "диспетчеризация") {
			t.Fatalf("missing present symbols info: %s", r)
		}
		// 8. Residual risk
		if !strings.Contains(r, "Остаточный риск") ||
			!strings.Contains(r, "v1.82.2") {
			t.Fatalf("missing residual risk or fixed version: %s", r)
		}
		// 9. Tracker closing
		if !strings.Contains(r, "Текст выше можно использовать в задаче трекера как обоснование статуса **Not Exploitable**") {
			t.Fatalf("missing tracker closing: %s", r)
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
		if !strings.Contains(r, "Not Affected (Уязвимость не применима к сервису)") ||
			!strings.Contains(r, "v2.0.0") ||
			!strings.Contains(r, "не входит в диапазон уязвимых версий") {
			t.Fatalf("unexpected rationale: %s", r)
		}
	})

	t.Run("exploitable renders remediation required", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-9999",
				Module:        "example.com/bad",
				FixedVersions: []string{"v1.1.0"},
			},
			Product: domain.ProductSnapshot{
				Repository: "vuln-service",
				Commit:     "def5678",
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.0.0",
			},
			EvidenceGraph: domain.EvidenceGraph{
				Exposures: []domain.ExposureFact{
					{CallSite: domain.CallSite{File: "main.go", Line: 20}, Direction: "inbound", Target: "net/http.ListenAndServe"},
				},
			},
			Verdict: &domain.VerdictResult{
				Verdict: domain.VerdictExploitable,
				Reason:  "all mandatory conditions met",
			},
		}

		r := TrackerRationale(c)
		if !strings.Contains(r, "Exploitable (Уязвимость подтверждена и эксплуатируема)") ||
			!strings.Contains(r, "Требуется исправление") ||
			!strings.Contains(r, "v1.1.0") {
			t.Fatalf("unexpected exploitable rationale: %s", r)
		}
	})
}

func TestMarkdownStructureInvertedPyramid(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-report-test",
		Vulnerability: domain.Vulnerability{
			ID:            "GO-2026-6443",
			Module:        "example.com/mod",
			FixedVersions: []string{"v1.2.0"},
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "abc12345",
			GoVersion:  "go1.26.1",
			GOOS:       "darwin",
			GOARCH:     "arm64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
		},
		Exploit: &domain.ExploitModel{
			Class:  "RESOURCE_EXHAUSTION",
			Impact: "Server panic (DoS)",
		},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{
				{Origin: domain.OriginInternalService, Summary: "test dataflow"},
			},
			ToolExecutions: []domain.ToolExecution{
				{Tool: "go", Args: []string{"version"}, ExitCode: 0, DurationMs: 10, StdoutSHA256: "abcdef1234567890"},
			},
		},
	}

	md := Markdown(c)

	// Ensure sections appear in the exact required order:
	idxHeader := strings.Index(md, "# Анализ уязвимости: GO-2026-6443")
	idxVerdict := strings.Index(md, "## Вердикт: `NO_EXPLOIT_PATH_FOUND`")
	idxVerdictBlockquote := strings.Index(md, "> **Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)**")
	idxRationale := strings.Index(md, "## Резюме")
	idxRemediation := strings.Index(md, "## Рекомендации по устранению")
	idxEvidence := strings.Index(md, "## Доказательная база")
	idxAudit := strings.Index(md, "## Технические детали и аудит (Data Flows, Tool Executions, Limitations)")
	idxDataFlows := strings.Index(md, "### Потоки данных (Data Flows)")
	idxToolExec := strings.Index(md, "### Журнал инструментов (Tool Executions)")

	if idxHeader == -1 || idxVerdict == -1 || idxVerdictBlockquote == -1 || idxRationale == -1 || idxRemediation == -1 ||
		idxEvidence == -1 || idxAudit == -1 || idxDataFlows == -1 || idxToolExec == -1 {
		t.Fatalf("one or more expected sections missing from Markdown output:\n%s", md)
	}

	if !(idxHeader < idxVerdict &&
		idxVerdict < idxVerdictBlockquote &&
		idxVerdictBlockquote < idxRationale &&
		idxRationale < idxRemediation &&
		idxRemediation < idxEvidence &&
		idxEvidence < idxAudit &&
		idxAudit < idxDataFlows &&
		idxDataFlows < idxToolExec) {
		t.Fatalf("sections are not in inverted pyramid order. Indices:\nheader=%d, verdict=%d, quote=%d, rationale=%d, remediation=%d, evidence=%d, audit=%d, dataFlows=%d, toolExec=%d",
			idxHeader, idxVerdict, idxVerdictBlockquote, idxRationale, idxRemediation, idxEvidence, idxAudit, idxDataFlows, idxToolExec)
	}
	if strings.Contains(md, "<details>") || strings.Contains(md, "<summary>") {
		t.Fatalf("markdown should not contain <details> or <summary> tags")
	}
}

func TestMarkdownStructureInvertedPyramid_FullSections(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-report-full",
		Vulnerability: domain.Vulnerability{
			ID:            "CVE-2026-12345",
			Module:        "example.com/mod",
			FixedVersions: []string{"v1.2.0"},
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/mod/vulnpkg"},
			},
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "1234567890ab",
			GoVersion:  "go1.26.1",
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			ModulePresent:   domain.ClaimTrue,
			PackagePresent:  domain.ClaimFalse,
			Limitations:     []string{"affected limitation 1"},
		},
		Claims: []domain.Claim{
			{ConditionID: "C-LOCUS", Result: domain.ClaimFalse},
		},
		RootCause: &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{
				{Package: "example.com/mod/vulnpkg", Symbol: "VulnFunc", Role: domain.RootCauseSink, Mechanism: "out-of-bounds read"},
			},
		},
		Exploit: &domain.ExploitModel{
			Class:  "MEMORY_CORRUPTION",
			Impact: "Remote Code Execution",
			MandatoryConditions: []domain.Condition{
				{ID: "C-LOCUS", Kind: "code", Description: "vulnerable function called"},
			},
			SupportingFactors: []domain.Condition{
				{ID: "C-INPUT", Kind: "input", Description: "untrusted input provided"},
			},
			NonLocusBasis: []domain.LocusDecision{
				{Symbol: domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "SafeFunc"}, Authority: "expert", Basis: "safe helper"},
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{CallSite: domain.CallSite{File: "main.go", Line: 42}, Direction: "inbound", Target: "net/http.ListenAndServe"},
			},
			DataFlows: []domain.DataFlow{
				{Origin: domain.OriginExternalUntrusted, Summary: "query param flows to sink"},
			},
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 150, StdoutSHA256: "fedcba0987654321"},
			},
			Runtime: []domain.EvidenceID{"EV-RUNTIME-1"},
			Evidence: []domain.Evidence{
				{ID: "EV-RUNTIME-1", Kind: domain.EvidenceRuntime, Source: "runtime-env", Content: "go version go1.26.1"},
				{ID: "EV-BUILD-1", Kind: domain.EvidenceBuild, Source: "go build", Content: "build successful\nall targets ok"},
			},
			Limitations: []string{"graph limitation 1"},
		},
		Hypotheses: []domain.Hypothesis{
			{ID: "H-1", ConditionID: "C-LOCUS", Status: domain.HypothesisRejected, Statement: "package not linked"},
		},
		Reviews: []domain.Review{
			{
				ID:     "REV-1",
				Result: domain.ReviewAccept,
				Findings: []domain.ReviewFinding{
					{Severity: "LOW", TargetType: "claim", TargetID: "C-LOCUS", Problem: "minor verification note"},
				},
			},
		},
	}

	md := Markdown(c)

	expectedSectionsInOrder := []string{
		"# Анализ уязвимости: CVE-2026-12345",
		"## Вердикт: `NO_EXPLOIT_PATH_FOUND`",
		"> **Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)**",
		"## Резюме",
		"## Рекомендации по устранению",
		"## Доказательная база",
		"### Источники и методы проверки (Методология)",
		"### Применимость (Affected Analysis)",
		"### Статус условий эксплуатации (Claims)",
		"### Точки входа (Exposure Facts)",
		"### Модель эксплуатации и сайты дефекта",
		"## Технические детали и аудит (Data Flows, Tool Executions, Limitations)",
		"### Потоки данных (Data Flows)",
		"### Журнал инструментов (Tool Executions)",
		"### Ограничения анализа (Limitations)",
		"### Рецензирование (Review Findings)",
		"### Факты среды (Runtime Facts)",
		"### Сборка и тесты (Build & Test)",
		"### Рабочие гипотезы (Hypotheses)",
	}

	lastIdx := -1
	for _, sec := range expectedSectionsInOrder {
		idx := strings.Index(md, sec)
		if idx == -1 {
			t.Fatalf("expected section %q not found in Markdown output:\n%s", sec, md)
		}
		if idx <= lastIdx {
			t.Fatalf("section %q at index %d is out of order (previous at %d)", sec, idx, lastIdx)
		}
		lastIdx = idx
	}
}

func sampleCaseForLocalization() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: "case-loc-test",
		Vulnerability: domain.Vulnerability{
			ID:            "GO-2026-6443",
			Module:        "example.com/mod",
			FixedVersions: []string{"v1.2.0"},
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/mod/vulnpkg"},
			},
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "1234567890ab",
			GoVersion:  "go1.26.1",
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			ModulePresent:   domain.ClaimTrue,
			PackagePresent:  domain.ClaimFalse,
			BuildRelevant:   domain.ClaimTrue,
			CheckedModules:  []string{"example.com/mod"},
			SelectedModules: []string{"example.com/mod"},
			PendingModules:  []string{"example.com/pending"},
			CheckedPackages: []string{"example.com/mod/vulnpkg"},
			EvidenceIDs:     []domain.EvidenceID{"EV-AFF-1"},
			Limitations:     []string{"affected limitation"},
		},
		Claims: []domain.Claim{
			{
				ConditionID: "C-LOCUS",
				Result:      domain.ClaimFalse,
				Falsifier:   "locus-package-absent",
				NegativeVerification: &domain.NegativeVerification{
					Status: domain.NegativeVerified,
				},
				EvidenceIDs: []domain.EvidenceID{"EV-CLM-1"},
			},
		},
		RootCause: &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{
				{Package: "example.com/mod/vulnpkg", Symbol: "VulnFunc", Role: domain.RootCauseSink, Mechanism: "out-of-bounds read"},
			},
		},
		Exploit: &domain.ExploitModel{
			Class:  "MEMORY_CORRUPTION",
			Impact: "Remote Code Execution",
			MandatoryConditions: []domain.Condition{
				{ID: "C-LOCUS", Kind: "code", Description: "vulnerable function called"},
				{ID: "C-REACH", Kind: "code", Description: "symbol reachable"},
				{ID: "C-PEER-INPUT", Kind: "input", Description: "peer input controlled"},
				{ID: "C-CONSTRAINT", Kind: "constraint", Description: "constraint violation"},
			},
			SupportingFactors: []domain.Condition{
				{ID: "C-EXPOSURE", Kind: "network", Description: "network reachable"},
				{ID: "C-TLS-VERIFY", Kind: "tls", Description: "tls verify disabled"},
			},
			NonLocusBasis: []domain.LocusDecision{
				{Symbol: domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "SafeFunc"}, Authority: "эксперт", Basis: "safe helper"},
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{CallSite: domain.CallSite{File: "main.go", Line: 42}, Direction: "inbound", Target: "net/http.ListenAndServe"},
			},
			DataFlows: []domain.DataFlow{
				{Origin: domain.OriginExternalUntrusted, Summary: "query param flows to sink"},
			},
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 150, StdoutSHA256: "fedcba0987654321"},
			},
			Runtime: []domain.EvidenceID{"EV-RUNTIME-1"},
			Evidence: []domain.Evidence{
				{ID: "EV-RUNTIME-1", Kind: domain.EvidenceRuntime, Source: "runtime-env", Content: "go version go1.26.1"},
				{ID: "EV-BUILD-1", Kind: domain.EvidenceBuild, Source: "go build", Content: "build successful\nall targets ok"},
			},
			Limitations: []string{"graph limitation 1"},
		},
		Hypotheses: []domain.Hypothesis{
			{ID: "H-1", ConditionID: "C-LOCUS", Status: domain.HypothesisRejected, Statement: "package not linked"},
		},
		Reviews: []domain.Review{
			{
				ID:     "REV-1",
				Result: domain.ReviewAccept,
				Findings: []domain.ReviewFinding{
					{Severity: "LOW", TargetType: "claim", TargetID: "C-LOCUS", Problem: "minor verification note"},
				},
			},
		},
	}
}

func TestMarkdownLocalizationRU(t *testing.T) {
	c := sampleCaseForLocalization()

	for _, md := range []string{Markdown(c, "ru"), Markdown(c)} { // both explicit "ru" and default
		expectedPhrases := []string{
			"# Анализ уязвимости: GO-2026-6443",
			"- Кейс: `case-loc-test`",
			"- Репозиторий: `example.com/product`",
			"- Коммит: `1234567890ab`",
			"- Окружение Go: `go1.26.1` (linux/amd64)",
			"## Вердикт: `NO_EXPLOIT_PATH_FOUND`",
			"> **Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)**",
			"## Резюме",
			"## Рекомендации по устранению",
			"Обновите зависимость `example.com/mod` с `v1.0.0` до `v1.2.0` (совместимо по SemVer: minor/patch, без изменения импортов):",
			"## Доказательная база",
			"### Применимость (Affected Analysis)",
			"| Проверка | Результат |",
			"| Наличие модуля в зависимостях |",
			"| Разрешённая версия в go.mod |",
			"| Версия входит в диапазон уязвимых |",
			"| Уязвимый пакет входит в сборку |",
			"| Код компилируется для целевой платформы |",
			"| Проверенные модули |",
			"| Скомпилированные модули |",
			"| Модули с неопределённой версией |",
			"| Проверенные пакеты |",
			"| Идентификаторы доказательств (Evidence IDs) |",
			"### Статус условий эксплуатации (Claims)",
			"| Условие | Результат | Верификация | Доказательства |",
			"Пакет отсутствует в сборке / ПОДТВЕРЖДЕНО",
			"### Точки входа (Exposure Facts)",
			"Входящий слушатель через `net/http.ListenAndServe`",
			"### Модель эксплуатации и сайты дефекта",
			"#### Первопричина дефекта (Root cause): Определена",
			"VulnFunc` (Точка сбоя / Sink)",
			"Класс дефекта: `MEMORY_CORRUPTION`",
			"Последствия: Remote Code Execution",
			"#### Обязательные условия (Mandatory conditions)",
			"Выполнение уязвимого кода: пакеты дефектного кода входят в граф сборки приложения",
			"Достижимость символов: хотя бы одна из уязвимых функций вызывается в коде продукта",
			"Контроль ввода: параметры уязвимой функции контролируются удалённым клиентом",
			"Нарушение ограничений: удалённый клиент может передать входные данные, вызывающие сбой",
			"#### Сопутствующие факторы (Supporting factors)",
			"Сетевая доступность: наличие открытых сетевых портов или исходящих подключений",
			"Проверка TLS: отключение проверки сертификатов позволяет передавать трафик без доверенного канала",
			"### Источники и методы проверки (Методология)",
			"| Статический анализ вызовов (govulncheck) |",
			"#### Функции без дефекта (исключены из анализа уязвимости)",
			"## Технические детали и аудит (Data Flows, Tool Executions, Limitations)",
			"### Потоки данных (Data Flows)",
			"### Журнал инструментов (Tool Executions)",
			"| Инструмент | Аргументы | Код возврата | Длительность (мс) | SHA-256 вывода |",
			"### Ограничения анализа (Limitations)",
			"### Рецензирование (Review Findings)",
			"### Факты среды (Runtime Facts)",
			"### Сборка и тесты (Build & Test)",
			"### Рабочие гипотезы (Hypotheses)",
		}

		for _, phrase := range expectedPhrases {
			if !strings.Contains(md, phrase) {
				t.Errorf("RU markdown missing expected phrase: %q", phrase)
			}
		}

		if strings.Contains(md, "<details>") || strings.Contains(md, "<summary>") {
			t.Errorf("RU markdown should not contain <details> or <summary> tags")
		}
		if strings.Contains(md, "# Vulnerability analysis:") {
			t.Errorf("RU markdown should not contain English header '# Vulnerability analysis:'")
		}
		if strings.Contains(md, "## Резюме для трекера (Tracker-ready rationale)") {
			t.Errorf("RU markdown should use strictly '## Резюме', not old verbose header")
		}
	}
}

func TestMarkdownLocalizationEN(t *testing.T) {
	c := sampleCaseForLocalization()
	md := Markdown(c, "en")

	expectedPhrases := []string{
		"# Vulnerability analysis: GO-2026-6443",
		"- Case: `case-loc-test`",
		"- Repository: `example.com/product`",
		"- Commit: `1234567890ab`",
		"- Go: `go1.26.1` (linux/amd64)",
		"## Verdict: `NO_EXPLOIT_PATH_FOUND`",
		"> **mandatory exploit condition is proven false**",
		"## Executive Summary",
		"## Remediation",
		"Update `example.com/mod` from `v1.0.0` to `v1.2.0` (SemVer drop-in: minor/patch, no import path changes):",
		"## Evidence Dossier",
		"### Verification Sources & Methods (Methodology)",
		"### Affected Analysis",
		"| check | result |",
		"| module present |",
		"| package present |",
		"| static call analysis (govulncheck) |",
		"### Claims Status",
		"| condition | result | verification | evidence |",
		"locus-package-absent / VERIFIED",
		"### Exposure Facts",
		"`inbound`",
		"### Exploit Model & Defect Locus",
		"#### Root cause: `RESOLVED`",
		"Class: `MEMORY_CORRUPTION`",
		"Impact: Remote Code Execution",
		"#### Mandatory conditions",
		"#### Supporting factors",
		"## Technical Details & Audit (Data Flows, Tool Executions, Limitations)",
		"### Data Flows",
		"### Tool Executions",
		"| tool | args | exit | ms | stdout sha256 |",
		"### Limitations",
		"### Review Findings",
		"### Runtime Facts",
		"### Build & Test",
		"### Hypotheses",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(md, phrase) {
			t.Errorf("EN markdown missing expected phrase: %q", phrase)
		}
	}

	if strings.Contains(md, "<details>") || strings.Contains(md, "<summary>") {
		t.Errorf("EN markdown should not contain <details> or <summary> tags")
	}
	if strings.Contains(md, "# Анализ уязвимости:") {
		t.Errorf("EN markdown should not contain Russian header '# Анализ уязвимости:'")
	}
	if strings.Contains(md, "## Резюме") {
		t.Errorf("EN markdown should not contain '## Резюме'")
	}
}

func TestReportWriteGeneratesBothRUandEN(t *testing.T) {
	c := sampleCaseForLocalization()
	dir := t.TempDir()

	if err := Write(dir, c); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	ruBytes, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatalf("reading report.md: %v", err)
	}
	ruContent := string(ruBytes)
	if !strings.Contains(ruContent, "# Анализ уязвимости: GO-2026-6443") || !strings.Contains(ruContent, "## Резюме") {
		t.Fatalf("report.md does not contain expected RU content:\n%s", ruContent)
	}

	enBytes, err := os.ReadFile(filepath.Join(dir, "report.en.md"))
	if err != nil {
		t.Fatalf("reading report.en.md: %v", err)
	}
	enContent := string(enBytes)
	if !strings.Contains(enContent, "# Vulnerability analysis: GO-2026-6443") || !strings.Contains(enContent, "## Executive Summary") {
		t.Fatalf("report.en.md does not contain expected EN content:\n%s", enContent)
	}

	for _, name := range []string{"report.json", "openvex.json", "cyclonedx.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected file %s to exist: %v", name, err)
		}
	}
}

func TestReportNoDetailsTags(t *testing.T) {
	c := sampleCaseForLocalization()
	for _, lang := range []string{"ru", "en"} {
		md := Markdown(c, lang)
		if strings.Contains(md, "<details>") {
			t.Errorf("[%s] output should not contain <details>", lang)
		}
		if strings.Contains(md, "</details>") {
			t.Errorf("[%s] output should not contain </details>", lang)
		}
		if strings.Contains(md, "<summary>") || strings.Contains(md, "</summary>") {
			t.Errorf("[%s] output should not contain <summary> tags", lang)
		}
	}

	mdRU := Markdown(c, "ru")
	if !strings.Contains(mdRU, "## Технические детали и аудит (Data Flows, Tool Executions, Limitations)") {
		t.Errorf("RU output missing expected audit header")
	}

	mdEN := Markdown(c, "en")
	if !strings.Contains(mdEN, "## Technical Details & Audit (Data Flows, Tool Executions, Limitations)") {
		t.Errorf("EN output missing expected audit header")
	}
}

func TestReportClarityAndProvenance(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-clarity-test",
		Vulnerability: domain.Vulnerability{
			ID:     "CVE-2026-6443",
			Module: "example.com/mod",
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/mod/vulnpkg"},
			},
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "1234567890ab",
			GoVersion:  "1.24.0",
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimFalse,
			BuildRelevant:   domain.ClaimTrue,
		},
		Claims: []domain.Claim{
			{ConditionID: "C-LOCUS", Result: domain.ClaimFalse},
			{ConditionID: "C-REACH", Result: domain.ClaimTrue},
			{ConditionID: "C-PEER-INPUT", Result: domain.ClaimUnknown},
		},
		RootCause: &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{
				{
					Package:   "example.com/mod/vulnpkg",
					Symbol:    "FaultyFunc",
					Role:      domain.RootCauseSink,
					Mechanism: "advisory-listed affected symbol",
				},
			},
		},
		Exploit: &domain.ExploitModel{
			Class:  "DENIAL_OF_SERVICE",
			Impact: "Server crash",
			MandatoryConditions: []domain.Condition{
				{ID: "C-LOCUS", Kind: "code", Description: "vulnerable function called"},
			},
			NonLocusBasis: []domain.LocusDecision{
				{
					Symbol:    domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "SafeDispatcher"},
					Authority: "accepted-machine-proposal",
					Basis:     "helper dispatcher (accepted-machine-proposal)",
				},
			},
			LocusSubjects: []domain.SymbolRef{
				{Package: "example.com/mod/vulnpkg", Symbol: "FaultyFunc"},
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 120, StdoutSHA256: "abcdef123456"},
			},
			Evidence: []domain.Evidence{
				{Kind: domain.EvidencePackageList, Content: "example.com/mod/vulnpkg\n"},
			},
		},
	}

	md := Markdown(c, "ru")

	// 1. Humanize Affected Analysis booleans in Russian: TRUE -> Да, FALSE -> Нет, UNKNOWN -> Не определено
	if !strings.Contains(md, "| Наличие модуля в зависимостях | Да |") {
		t.Errorf("expected '| Наличие модуля в зависимостях | Да |', got:\n%s", md)
	}
	if !strings.Contains(md, "| Версия входит в диапазон уязвимых | Да |") {
		t.Errorf("expected '| Версия входит в диапазон уязвимых | Да |'")
	}
	if !strings.Contains(md, "| Уязвимый пакет входит в сборку | Нет |") {
		t.Errorf("expected '| Уязвимый пакет входит в сборку | Нет |'")
	}
	if !strings.Contains(md, "| Код компилируется для целевой платформы | Да |") {
		t.Errorf("expected '| Код компилируется для целевой платформы | Да |'")
	}
	if strings.Contains(md, "| Наличие модуля в зависимостях | TRUE |") || strings.Contains(md, "| Уязвимый пакет входит в сборку | FALSE |") {
		t.Errorf("Affected table should not contain raw TRUE/FALSE booleans")
	}

	// 2. Humanize Claims table in Russian:
	// TRUE -> Подтверждено (TRUE), FALSE -> Опровергнуто (FALSE), UNKNOWN -> Не определено (UNKNOWN)
	if !strings.Contains(md, "| `C-LOCUS` | Опровергнуто (FALSE) |") {
		t.Errorf("expected C-LOCUS to show 'Опровергнуто (FALSE)'")
	}
	if !strings.Contains(md, "| `C-REACH` | Подтверждено (TRUE) |") {
		t.Errorf("expected C-REACH to show 'Подтверждено (TRUE)'")
	}
	if !strings.Contains(md, "| `C-PEER-INPUT` | Не определено (UNKNOWN) |") {
		t.Errorf("expected C-PEER-INPUT to show 'Не определено (UNKNOWN)'")
	}

	// 3. Root Causes: advisory-listed affected symbol -> заявлена как уязвимая в базе (advisory)
	if !strings.Contains(md, "заявлена как уязвимая в базе (advisory)") {
		t.Errorf("expected 'заявлена как уязвимая в базе (advisory)' in root causes")
	}
	if strings.Contains(md, "advisory-listed affected symbol") {
		t.Errorf("should not contain 'advisory-listed affected symbol'")
	}

	// 4. Locus Exclusions:
	// Header: #### Функции без дефекта (исключены из анализа уязвимости)
	// Text: Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции:
	// Notes: replace accepted-machine-proposal with принятая рекомендация анализатора
	if !strings.Contains(md, "#### Функции без дефекта (исключены из анализа уязвимости)") {
		t.Errorf("missing Locus Exclusions header: '#### Функции без дефекта (исключены из анализа уязвимости)'")
	}
	if strings.Contains(md, "#### Экспертные решения non_locus") {
		t.Errorf("should not contain old header '#### Экспертные решения non_locus'")
	}
	if !strings.Contains(md, "Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции:") {
		t.Errorf("missing humanized Locus Exclusions description")
	}
	if !strings.Contains(md, "принятая рекомендация анализатора") {
		t.Errorf("expected 'принятая рекомендация анализатора' in place of 'accepted-machine-proposal'")
	}
	if strings.Contains(md, "accepted-machine-proposal") {
		t.Errorf("should not contain 'accepted-machine-proposal'")
	}

	// 5. Govulncheck status in Affected Analysis table
	if !strings.Contains(md, "| Статический анализ вызовов (govulncheck) | Трасса вызовов от кода продукта не обнаружена (чисто) |") {
		t.Errorf("missing govulncheck status row in Affected Analysis table")
	}

	// 6. Provenance Breakdown under ## Доказательная база: ### Источники и методы проверки (Методология)
	expectedProvenancePhrases := []string{
		"### Источники и методы проверки (Методология)",
		"⚙️ **Детерминированные проверки компилятора Go:**",
		"Зависимости (`go.mod` / `go list -m`): фиксация версий библиотек в сборке.",
		"Граф пакетов сборки (`go list -deps`): проверка фактического включения скомпилированных пакетов в бинарный файл.",
		"Анализ графа вызовов (`govulncheck`): поиск статических путей вызова от приложения к функциям из advisory (проверка достижимости символов).",
		"Анализ точек входа (AST): инспекция конструкторов и инициализации сервисов в коде проекта.",
		"🤖 **Семантический анализ LLM (AI-исследование):**",
		"Архитектурный анализ уязвимости: исследование патча и разделение функций из advisory на сайт сбоя (дефектный локус) и вспомогательные функции (диспетчеры).",
		"Семантическое рецензирование: валидация логики работы компонентов и проверка условий эксплуатации.",
	}
	for _, phrase := range expectedProvenancePhrases {
		if !strings.Contains(md, phrase) {
			t.Errorf("provenance breakdown missing expected phrase: %q", phrase)
		}
	}

	if strings.Contains(md, "non_locus") {
		t.Errorf("Russian report should not contain raw 'non_locus' jargon, got:\n%s", md)
	}
}

func TestGovulncheckComparisonAndDivergence(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "GO-2026-6443-test",
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2026-6443",
			Module: "google.golang.org/grpc",
		},
		Product: domain.ProductSnapshot{
			Repository: "my-service",
			Commit:     "b740a8b0cf1e",
			GoVersion:  "go1.26.1",
			GOOS:       "darwin",
			GOARCH:     "arm64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.83.0",
			ModulePresent:   domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{
			Class:  "RESOURCE_EXHAUSTION",
			Impact: "Server panic",
			NonLocusBasis: []domain.LocusDecision{
				{
					Symbol:    domain.SymbolRef{Package: "google.golang.org/grpc/internal/transport", Symbol: "HandleStreams"},
					Authority: "accepted-machine-proposal",
					Basis:     "helper dispatcher (accepted-machine-proposal)",
				},
			},
			LocusSubjects: []domain.SymbolRef{
				{Package: "google.golang.org/grpc/internal/transport", Symbol: "HandleStreams"},
				{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			CallPaths: []domain.CallPath{
				{
					Frames: []domain.CallSite{
						{Package: "google.golang.org/grpc/internal/transport", Function: "HandleStreams", File: "internal/transport/http2_server.go", Line: 639},
						{Package: "main", Function: "main", File: "main.go", Line: 27},
					},
				},
			},
			Evidence: []domain.Evidence{
				{Kind: domain.EvidencePackageList, Content: "google.golang.org/grpc/internal/transport\n"},
			},
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 150},
			},
		},
	}

	// 1. Russian report
	mdRU := Markdown(c, "ru")
	if !strings.Contains(mdRU, "### Сопоставление с govulncheck (Анализ расхождения)") {
		t.Errorf("missing Russian divergence header")
	}
	if !strings.Contains(mdRU, "🔍 **Вердикт govulncheck:** **Уязвимый код вызывается (Reachable)**") {
		t.Errorf("missing govulncheck reachable verdict in Russian")
	}
	if !strings.Contains(mdRU, "google.golang.org/grpc/internal/transport.HandleStreams") {
		t.Errorf("missing called symbol in govulncheck section")
	}
	if !strings.Contains(mdRU, "🛡️ **Вердикт анализатора:** **`NO_EXPLOIT_PATH_FOUND` (Уязвимый путь исполнения отсутствует)**") {
		t.Errorf("missing analyzer verdict in divergence section")
	}
	if !strings.Contains(mdRU, "Обоснование опровержения (почему срабатывание govulncheck является ложной тревогой):") {
		t.Errorf("missing refutation rationale header in Russian")
	}
	if !strings.Contains(mdRU, "reachability false positive") {
		t.Errorf("missing reachability false positive conclusion")
	}

	// In Tracker Rationale (## Резюме):
	if !strings.Contains(mdRU, "Сопоставление со сканером: `govulncheck` отмечает уязвимость как вызываемую (Reachable)") {
		t.Errorf("missing govulncheck refutation in tracker rationale")
	}

	// 2. English report
	mdEN := Markdown(c, "en")
	if !strings.Contains(mdEN, "### Govulncheck Comparison & Divergence Analysis") {
		t.Errorf("missing English divergence header")
	}
	if !strings.Contains(mdEN, "Govulncheck Finding:** **Reachable (Vulnerable code is called)**") {
		t.Errorf("missing govulncheck reachable verdict in English")
	}
	if !strings.Contains(mdEN, "Divergence Rationale (Why govulncheck's warning is refuted):") {
		t.Errorf("missing refutation rationale header in English")
	}
	if !strings.Contains(mdEN, "reachability false positive") {
		t.Errorf("missing reachability false positive conclusion in English")
	}
}

func TestReportGovulncheckCleanComparison(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "CASE-CLEAN",
		Vulnerability: domain.Vulnerability{
			ID:     "GO-TEST-2",
			Module: "example.com/dep",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNotAffected,
			Reason:  "package is not linked in build",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			ModulePresent:   domain.ClaimTrue,
			PackagePresent:  domain.ClaimFalse,
			BuildRelevant:   domain.ClaimFalse,
		},
		EvidenceGraph: domain.EvidenceGraph{
			CallPaths: nil, // Clean: zero call paths
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 120},
			},
		},
	}

	mdRU := Markdown(c, "ru")
	if !strings.Contains(mdRU, "Трасса вызовов не обнаружена (Clean)") {
		t.Errorf("missing Clean govulncheck status in Russian")
	}
	if !strings.Contains(mdRU, "Трасса вызовов от кода продукта не обнаружена (чисто)") {
		t.Errorf("missing clean summary in affected table in Russian")
	}

	mdEN := Markdown(c, "en")
	if !strings.Contains(mdEN, "Clean (No call path found)") {
		t.Errorf("missing Clean govulncheck status in English")
	}
}

func TestReportGovulncheckCleanMissingCallDivergence(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "CASE-MISSING-CALL",
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2020-0017",
			Module: "github.com/dgrijalva/jwt-go",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
			Reason:  "all mandatory exploit conditions are satisfied",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v3.2.0+incompatible",
			ModulePresent:   domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		EvidenceGraph: domain.EvidenceGraph{
			CallPaths: nil,
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 120},
			},
			Evidence: []domain.Evidence{
				{
					ID:      "EV-MISSING-CALL",
					Tool:    "goanalysis.Index.CheckMissingCall",
					Content: "security check MapClaims.VerifyAudience is omitted on active pipeline MapClaims.Valid",
				},
			},
		},
	}

	mdRU := Markdown(c, "ru")
	if !strings.Contains(mdRU, "Сопоставление (Расхождение с govulncheck)") {
		t.Errorf("missing divergence header in Russian")
	}
	if !strings.Contains(mdRU, "missing-call") {
		t.Errorf("missing missing-call explanation in Russian")
	}

	mdEN := Markdown(c, "en")
	if !strings.Contains(mdEN, "Divergence Rationale:") {
		t.Errorf("missing divergence rationale in English")
	}
	if !strings.Contains(mdEN, "missing-call") {
		t.Errorf("missing missing-call explanation in English")
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

func TestReportTriageAssessmentTable(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-triage-test",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-9999",
			BaseSeverity: "CRITICAL",
			BaseScore:    10.0,
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/repo",
			Commit:     "commit123456",
			GoVersion:  "go1.26.1",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
			Reason:  "all mandatory conditions met",
		},
		ContextualRisk: &domain.ContextualRisk{
			Status:           domain.RiskStatusAssessed,
			BaseSeverity:     "CRITICAL",
			BaseScore:        10.0,
			ContextualLevel:  domain.RiskLevelMedium,
			ContextualScore:  4.5,
			Priority:         domain.PriorityP2,
			SLA:              "Sprint (30 days)",
			AdjustmentReason: "Сетевой доступ из внешней сети отсутствует (слушатель привязан к локальному интерфейсу 127.0.0.1).",
		},
	}

	// 1. Check Russian markdown
	mdRU := Markdown(c, "ru")
	if !strings.Contains(mdRU, "## Контекстная критичность и триаж (Triage Assessment)") {
		t.Fatalf("RU markdown missing triage heading:\n%s", mdRU)
	}
	if !strings.Contains(mdRU, "🔴 **CRITICAL** (CVSS 10.0)") {
		t.Errorf("RU markdown missing nominal severity:\n%s", mdRU)
	}
	if !strings.Contains(mdRU, "🟡 **MEDIUM** (Score 4.5)") {
		t.Errorf("RU markdown missing contextual severity:\n%s", mdRU)
	}
	if !strings.Contains(mdRU, "**P0 (Blocker)**") {
		t.Errorf("RU markdown missing nominal priority:\n%s", mdRU)
	}
	if !strings.Contains(mdRU, "**P2 (Плановый спринт)**") {
		t.Errorf("RU markdown missing contextual priority:\n%s", mdRU)
	}
	if !strings.Contains(mdRU, "> ℹ️ **Обоснование переоценки:**") {
		t.Errorf("RU markdown missing adjustment reason header:\n%s", mdRU)
	}

	// 2. Check English markdown
	mdEN := Markdown(c, "en")
	if !strings.Contains(mdEN, "## Contextual Severity & Triage Assessment") {
		t.Fatalf("EN markdown missing triage heading:\n%s", mdEN)
	}
	if !strings.Contains(mdEN, "**P2 (Scheduled Sprint)**") {
		t.Errorf("EN markdown missing contextual priority:\n%s", mdEN)
	}
	if !strings.Contains(mdEN, "> ℹ️ **Triage Rationale:**") {
		t.Errorf("EN markdown missing triage rationale header:\n%s", mdEN)
	}

	// 3. Test report.Write serialization
	tmpDir := t.TempDir()
	if err := Write(tmpDir, c); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	repJSON, err := os.ReadFile(filepath.Join(tmpDir, "report.json"))
	if err != nil {
		t.Fatalf("reading report.json: %v", err)
	}
	if !strings.Contains(string(repJSON), `"contextual_risk"`) {
		t.Fatalf("report.json missing contextual_risk: %s", string(repJSON))
	}
	if !strings.Contains(string(repJSON), `"priority": "P2"`) {
		t.Fatalf("report.json missing priority P2: %s", string(repJSON))
	}
}

func TestReportMarkdown_DualTrackPerimeterMatrix_RU(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID: "CVE-2026-TEST",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		DetectedPerimeter:  domain.PerimeterClusterInternal,
		PerimeterRationale: "ClusterIP service found",
		Profiles: []domain.ProfileVerdict{
			{
				Profile:        domain.ProfileZeroTrust,
				Title:          "Внешний периметр (Zero Trust / Недоверенный пир)",
				Verdict:        domain.VerdictInconclusive,
				Priority:       domain.PriorityP1,
				SLA:            "7 days",
				IsTargetActual: false,
			},
			{
				Profile:        domain.ProfileClusterPerimeter,
				Title:          "Внутренний кластер (K8s ClusterIP / Service Mesh)",
				Verdict:        domain.VerdictNoExploitPathFound,
				Priority:       domain.PriorityDismissed,
				SLA:            "No action",
				IsTargetActual: true,
			},
		},
	}

	md := Markdown(c, "ru")
	if !strings.Contains(md, "### Матрица сетевых периметров угроз") {
		t.Fatalf("expected matrix heading in RU report:\n%s", md)
	}
	if !strings.Contains(md, "- **Обнаруженный периметр развёртывания:** `Внутрикластерный (cluster-internal)`") {
		t.Errorf("expected detected perimeter in RU report:\n%s", md)
	}
	if !strings.Contains(md, "- **Обоснование периметра:** Обнаружен сервис ClusterIP") {
		t.Errorf("expected perimeter rationale in RU report:\n%s", md)
	}
	if !strings.Contains(md, "*(Фактический)*") {
		t.Errorf("expected *(Фактический)* in RU report:\n%s", md)
	}
	if !strings.Contains(md, "**DISMISSED**") {
		t.Errorf("expected DISMISSED in RU report:\n%s", md)
	}
	if !strings.Contains(md, "Действий не требуется: уязвимость закрыта сетевым периметром.") {
		t.Errorf("expected dismissed action recommendation in RU report:\n%s", md)
	}
	if !strings.Contains(md, "Высокий приоритет: устранение в течение 7 дней.") {
		t.Errorf("expected P1 action recommendation in RU report:\n%s", md)
	}

	lines := strings.Split(md, "\n")
	foundClusterActual := false
	for _, l := range lines {
		if strings.Contains(l, "Cluster") || strings.Contains(l, "Кластер") || strings.Contains(l, "кластер") {
			if strings.Contains(l, "*(Фактический)*") {
				foundClusterActual = true
				break
			}
		}
	}
	if !foundClusterActual {
		t.Errorf("expected *(Фактический)* to be on the cluster row:\n%s", md)
	}
}

func TestReportMarkdown_DualTrackPerimeterMatrix_EN(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID: "CVE-2026-TEST",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		DetectedPerimeter:  domain.PerimeterClusterInternal,
		PerimeterRationale: "ClusterIP service found",
		Profiles: []domain.ProfileVerdict{
			{
				Profile:        domain.ProfileZeroTrust,
				Title:          "Public Internet (Zero Trust)",
				Verdict:        domain.VerdictInconclusive,
				Priority:       domain.PriorityP1,
				SLA:            "7 days",
				IsTargetActual: false,
			},
			{
				Profile:        domain.ProfileClusterPerimeter,
				Title:          "Internal Cluster (ClusterIP)",
				Verdict:        domain.VerdictNoExploitPathFound,
				Priority:       domain.PriorityDismissed,
				SLA:            "No action",
				IsTargetActual: true,
			},
		},
	}

	md := Markdown(c, "en")
	if !strings.Contains(md, "### Security Perimeter Matrix") {
		t.Fatalf("expected matrix heading in EN report:\n%s", md)
	}
	if !strings.Contains(md, "- **Detected Deployment Perimeter:** `cluster-internal`") {
		t.Errorf("expected detected perimeter in EN report:\n%s", md)
	}
	if !strings.Contains(md, "- **Perimeter Rationale:** ClusterIP service found") {
		t.Errorf("expected perimeter rationale in EN report:\n%s", md)
	}
	if !strings.Contains(md, "*(Actual)*") {
		t.Errorf("expected *(Actual)* in EN report:\n%s", md)
	}
	if !strings.Contains(md, "**DISMISSED**") {
		t.Errorf("expected DISMISSED in EN report:\n%s", md)
	}
	if !strings.Contains(md, "No remediation required: vulnerability neutralized by network perimeter.") {
		t.Errorf("expected dismissed action recommendation in EN report:\n%s", md)
	}
	if !strings.Contains(md, "High priority: remediation within 7 days.") {
		t.Errorf("expected P1 action recommendation in EN report:\n%s", md)
	}

	lines := strings.Split(md, "\n")
	foundClusterActual := false
	for _, l := range lines {
		if strings.Contains(l, "Cluster") {
			if strings.Contains(l, "*(Actual)*") {
				foundClusterActual = true
				break
			}
		}
	}
	if !foundClusterActual {
		t.Errorf("expected *(Actual)* to be on the cluster row:\n%s", md)
	}
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
		ContextualRisk: &domain.ContextualRisk{
			BaseSeverity:    "MEDIUM",
			BaseScore:       5.0,
			ContextualLevel: domain.RiskLevelCritical,
			ContextualScore: 10.0,
			Priority:        domain.PriorityP0,
			Status:          domain.RiskStatusAssessed,
			SLA:             "24h (Immediate remediation required)",
		},
	}

	md := Markdown(c, "ru")

	if strings.Contains(md, "> **all mandatory exploit conditions are satisfied**") {
		t.Errorf("found raw English verdict reason in Russian report:\n%s", md)
	}
	if !strings.Contains(md, "> **Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)**") {
		t.Errorf("missing localized Russian verdict reason in report:\n%s", md)
	}

	if strings.Contains(md, "- **Обнаруженный периметр развёртывания:** `public`") {
		t.Errorf("found unlocalized perimeter 'public' in Russian report:\n%s", md)
	}
	if !strings.Contains(md, "- **Обнаруженный периметр развёртывания:** `Публичный (public)`") {
		t.Errorf("missing localized perimeter 'Публичный (public)' in Russian report:\n%s", md)
	}

	if strings.Contains(md, "- **Обоснование периметра:** public exposure detected: inbound listener :8080") {
		t.Errorf("found unlocalized perimeter rationale in Russian report:\n%s", md)
	}
	if !strings.Contains(md, "- **Обоснование периметра:** Обнаружен публичный доступ: входящий слушатель :8080") {
		t.Errorf("missing localized perimeter rationale in Russian report:\n%s", md)
	}

	if strings.Contains(md, "источник: literal") || strings.Contains(md, "область: all-interfaces") {
		t.Errorf("found unlocalized exposure metadata (literal/all-interfaces) in Russian report:\n%s", md)
	}
	if !strings.Contains(md, "источник: литерал, область: все интерфейсы (0.0.0.0)") {
		t.Errorf("missing localized exposure metadata (литерал, все интерфейсы) in Russian report:\n%s", md)
	}

	if strings.Contains(md, "24h (Immediate remediation required)") {
		t.Errorf("found unlocalized SLA '24h (Immediate remediation required)' in Russian report:\n%s", md)
	}
	if !strings.Contains(md, "24 часа (требуется немедленное устранение)") {
		t.Errorf("missing localized SLA '24 часа (требуется немедленное устранение)' in Russian report:\n%s", md)
	}
}

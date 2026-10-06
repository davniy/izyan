package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
)

// AuditMarkdown renders the technical audit document: every recorded claim,
// evidence entry, data flow, tool execution, review, hypothesis, internal
// machine proposal and limitation — the full fidelity layer that the human
// report deliberately drops. Sections with no data are skipped.
func AuditMarkdown(c *domain.AnalysisCase, lang ...string) string {
	ensureTriageAssessment(c)
	populateUpgradeCompatibility(c)
	isRU := isRussian(lang...)
	p := newReportPaths(c)
	var b strings.Builder
	if isRU {
		fmt.Fprintf(&b, "# %s — технический аудит\n\n", c.Vulnerability.ID)
	} else {
		fmt.Fprintf(&b, "# %s — technical audit\n\n", c.Vulnerability.ID)
	}
	writeAuditMetadata(&b, c, p, isRU)

	renderAuditAssessment(&b, c, p, isRU)
	renderAuditMethodology(&b, isRU)
	renderAuditAffected(&b, c, isRU)
	renderGovulncheckComparison(&b, c, isRU)
	renderAuditExploitModel(&b, c, p, isRU)
	renderAuditClaims(&b, c, p, isRU)
	renderAuditEvidence(&b, c, p, isRU)
	renderAuditExposures(&b, c, p, isRU)
	renderAuditDataFlows(&b, c, p, isRU)
	renderAuditClosures(&b, c, p, isRU)
	renderAuditTools(&b, c, p, isRU)
	renderAuditRuntime(&b, c, p, isRU)
	renderAuditBuildTest(&b, c, p, isRU)
	renderAuditReviews(&b, c, p, isRU)
	renderAuditHypotheses(&b, c, p, isRU)
	renderAuditAIArtifacts(&b, c, p, isRU)
	renderAuditMachineAssessment(&b, c, p, isRU)
	renderAuditProfiles(&b, c, p, isRU)
	renderAuditLimitations(&b, c, p, isRU)

	return b.String()
}

func writeAuditMetadata(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	writeCaseMetadata(b, c, isRU)
	if env := formatEnv(c, isRU); env != "" {
		if isRU {
			fmt.Fprintf(b, "- Окружение сборки:%s\n", env)
		} else {
			fmt.Fprintf(b, "- Build environment:%s\n", env)
		}
	}
	if c.Product.VendorMode {
		if isRU {
			b.WriteString("- Режим vendor: включён\n")
		} else {
			b.WriteString("- Vendor mode: enabled\n")
		}
	}
	if len(c.Product.DeployManifests) > 0 {
		var dm []string
		for _, d := range c.Product.DeployManifests {
			dm = append(dm, p.text(d))
		}
		if isRU {
			fmt.Fprintf(b, "- Deployment-манифесты: `%s`\n", strings.Join(dm, "`, `"))
		} else {
			fmt.Fprintf(b, "- Deployment manifests: `%s`\n", strings.Join(dm, "`, `"))
		}
	}
	if c.Product.DeployArchive != "" {
		if isRU {
			fmt.Fprintf(b, "- Архив манифестов: `%s`\n", p.text(c.Product.DeployArchive))
		} else {
			fmt.Fprintf(b, "- Manifest archive: `%s`\n", p.text(c.Product.DeployArchive))
		}
	}
	if c.Product.PerimeterOverride != "" {
		if isRU {
			fmt.Fprintf(b, "- Переопределение периметра: `%s`\n", c.Product.PerimeterOverride)
		} else {
			fmt.Fprintf(b, "- Perimeter override: `%s`\n", c.Product.PerimeterOverride)
		}
	}
	if c.Product.TrustedPeer {
		if isRU {
			b.WriteString("- Доверенный пир заявлен оператором (`--trusted-peer`): да\n")
		} else {
			b.WriteString("- Trusted peer declared by operator (`--trusted-peer`): yes\n")
		}
	}
	usage := c.UsageSnapshot()
	if isRU {
		fmt.Fprintf(b, "- Профиль анализа: `%s`; строгий LLM: %v; принятие машинных предложений локуса: %v\n",
			c.CVEAnalysisProfile, c.StrictLLM, c.AcceptLocusProposals)
		fmt.Fprintf(b, "- Использование: итераций %d, инструментов %d, LLM %d, чтений исходников %d, итераций ревью %d\n",
			usage.Iterations, usage.ToolCalls, usage.LLMCalls, usage.SourceReads, usage.ReviewIterations)
	} else {
		fmt.Fprintf(b, "- Analysis profile: `%s`; strict LLM: %v; accept locus proposals: %v\n",
			c.CVEAnalysisProfile, c.StrictLLM, c.AcceptLocusProposals)
		fmt.Fprintf(b, "- Usage: iterations %d, tool calls %d, LLM calls %d, source reads %d, review iterations %d\n",
			usage.Iterations, usage.ToolCalls, usage.LLMCalls, usage.SourceReads, usage.ReviewIterations)
	}
	if len(c.Workflow.Timings) > 0 {
		var keys []string
		var total float64
		for k, v := range c.Workflow.Timings {
			keys = append(keys, k)
			total += v
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%.1fs", k, c.Workflow.Timings[k]))
		}
		if isRU {
			fmt.Fprintf(b, "- Тайминги состояний: %s | всего=%.1fs\n", strings.Join(parts, " "), total)
		} else {
			fmt.Fprintf(b, "- State timings: %s | total=%.1fs\n", strings.Join(parts, " "), total)
		}
	}
	b.WriteString("\n")
}

// renderAuditAssessment prints the verdict verbatim and the full internal
// triage parameters — everything the human report intentionally omits.
func renderAuditAssessment(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if c.Verdict == nil && c.ContextualRisk == nil {
		return
	}
	if isRU {
		b.WriteString("## Результат и внутренние параметры triage\n\n")
	} else {
		b.WriteString("## Verdict and internal triage parameters\n\n")
	}
	if c.Verdict != nil {
		if isRU {
			fmt.Fprintf(b, "- **Вердикт:** `%s`\n", c.Verdict.Verdict)
			fmt.Fprintf(b, "- **Причина (сырая):** %s\n", p.text(c.Verdict.Reason))
		} else {
			fmt.Fprintf(b, "- **Verdict:** `%s`\n", c.Verdict.Verdict)
			fmt.Fprintf(b, "- **Reason (raw):** %s\n", p.text(c.Verdict.Reason))
		}
		if len(c.Verdict.ConditionIDs) > 0 {
			var ids []string
			for _, id := range c.Verdict.ConditionIDs {
				ids = append(ids, string(id))
			}
			if isRU {
				fmt.Fprintf(b, "- **Условия вердикта:** `%s`\n", strings.Join(ids, "`, `"))
			} else {
				fmt.Fprintf(b, "- **Verdict conditions:** `%s`\n", strings.Join(ids, "`, `"))
			}
		}
		if len(c.Verdict.EvidenceIDs) > 0 {
			fmt.Fprintf(b, "- **Evidence IDs:** %s\n", strings.Join(evidenceIDs(c.Verdict.EvidenceIDs), ", "))
		}
		if c.Verdict.GroundBasis != "" {
			if isRU {
				fmt.Fprintf(b, "- **Основание (ground_basis):** `%s`\n", c.Verdict.GroundBasis)
			} else {
				fmt.Fprintf(b, "- **Ground basis:** `%s`\n", c.Verdict.GroundBasis)
			}
		}
	}
	if r := c.ContextualRisk; r != nil {
		if isRU {
			b.WriteString("\n| Параметр | Значение |\n|---|---|\n")
		} else {
			b.WriteString("\n| Parameter | Value |\n|---|---|\n")
		}
		row := func(k, v string) {
			if v == "" {
				return
			}
			fmt.Fprintf(b, "| `%s` | %s |\n", k, sanitizeTableString(p.text(v), 200))
		}
		row("status", string(r.Status))
		row("base_severity", r.BaseSeverity)
		if r.BaseScore > 0 {
			row("base_score", fmt.Sprintf("%.1f", r.BaseScore))
		}
		row("severity_source", r.SeveritySource)
		row("score_source", r.ScoreSource)
		row("contextual_level", string(r.ContextualLevel))
		if r.ContextualScore > 0 {
			row("contextual_score", fmt.Sprintf("%.1f", r.ContextualScore))
		}
		row("priority", string(r.Priority))
		row("base_priority", string(r.BasePriority))
		row("triage_disposition", string(r.TriageDisposition))
		row("sla", r.SLA)
		row("adjustment_reason", r.AdjustmentReason)
		row("factors.verdict", r.Factors.Verdict)
		row("factors.exposure", r.Factors.Exposure)
		row("factors.authentication", r.Factors.Authentication)
		row("factors.payload_control", r.Factors.PayloadControl)
		row("factors.blast_radius", r.Factors.BlastRadius)
	}
	b.WriteString("\n")
}

// renderAuditMethodology documents the deterministic verification methods
// used by the analyzer (former provenance breakdown, audit-only now).
func renderAuditMethodology(b *strings.Builder, isRU bool) {
	if isRU {
		b.WriteString("## Источники и методы проверки\n\n")
		b.WriteString("- ⚙️ **Детерминированные проверки компилятора Go:**\n")
		b.WriteString("  - Зависимости (`go.mod` / `go list -m`): фиксация версий библиотек в сборке.\n")
		b.WriteString("  - Граф пакетов сборки (`go list -deps`): проверка фактического включения скомпилированных пакетов в бинарный файл.\n")
		b.WriteString("  - Анализ графа вызовов (`govulncheck`): поиск статических путей вызова от приложения к функциям из advisory (проверка достижимости символов).\n")
		b.WriteString("  - Анализ точек входа (AST): инспекция конструкторов и инициализации сервисов в коде проекта.\n")
		b.WriteString("  - Анализ сетевого периметра и манифестов: инспекция сетевых слушателей и манифестов развёртывания (K8s/Helm).\n\n")
	} else {
		b.WriteString("## Verification sources and methods\n\n")
		b.WriteString("- ⚙️ **Go compiler deterministic checks:**\n")
		b.WriteString("  - Dependencies (`go.mod` / `go list -m`): module version pinned in build.\n")
		b.WriteString("  - Build package graph (`go list -deps`): verification of whether library packages are physically linked into the compiled binary.\n")
		b.WriteString("  - Call graph analysis (`govulncheck`): detection of static call paths from product code to advisory symbols (reachability check).\n")
		b.WriteString("  - Entrypoint analysis (AST): inspection of service initialization and constructors used in project code.\n")
		b.WriteString("  - Network perimeter & manifest analysis: inspection of listeners and deployment manifests (K8s/Helm).\n\n")
	}
}

// renderAuditAffected prints the full AffectedResult record including the
// checked/selected/pending inventories.
func renderAuditAffected(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c.Affected == nil {
		return
	}
	a := c.Affected
	if isRU {
		b.WriteString("## Применимость\n\n")
		b.WriteString("| Проверка | Результат |\n|---|---|\n")
		fmt.Fprintf(b, "| Наличие модуля в зависимостях | %s |\n", localizeAffectedBool(a.ModulePresent, true))
		fmt.Fprintf(b, "| Разрешённая версия в go.mod | `%s` |\n", a.ResolvedVersion)
		fmt.Fprintf(b, "| Версия входит в диапазон уязвимых | %s |\n", localizeAffectedBool(a.VersionAffected, true))
		fmt.Fprintf(b, "| Уязвимый пакет входит в сборку | %s |\n", localizeAffectedBool(a.PackagePresent, true))
		fmt.Fprintf(b, "| Код компилируется для целевой платформы | %s |\n", localizeAffectedBool(a.BuildRelevant, true))
		fmt.Fprintf(b, "| Статический анализ вызовов (govulncheck) | %s |\n", govulncheckSummary(c, true))
		if len(a.CheckedModules) > 0 {
			fmt.Fprintf(b, "| Проверенные модули | `%s` |\n", strings.Join(a.CheckedModules, "`, `"))
		}
		if a.SelectedModule != "" {
			fmt.Fprintf(b, "| Выбранный модуль | `%s` |\n", a.SelectedModule)
		}
		if len(a.SelectedModules) > 0 {
			fmt.Fprintf(b, "| Скомпилированные модули | `%s` |\n", strings.Join(a.SelectedModules, "`, `"))
		}
		if len(a.PendingModules) > 0 {
			fmt.Fprintf(b, "| Модули с неопределённой версией | `%s` |\n", strings.Join(a.PendingModules, "`, `"))
		}
		if len(a.CheckedPackages) > 0 {
			fmt.Fprintf(b, "| Проверенные пакеты | `%s` |\n", strings.Join(a.CheckedPackages, "`, `"))
		}
		if len(a.EvidenceIDs) > 0 {
			fmt.Fprintf(b, "| Идентификаторы доказательств | %s |\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
		}
		b.WriteString("\n")
	} else {
		b.WriteString("## Applicability\n\n")
		b.WriteString("| check | result |\n|---|---|\n")
		fmt.Fprintf(b, "| module present | %s |\n", a.ModulePresent)
		fmt.Fprintf(b, "| resolved version | `%s` |\n", a.ResolvedVersion)
		fmt.Fprintf(b, "| version affected | %s |\n", a.VersionAffected)
		fmt.Fprintf(b, "| package present | %s |\n", a.PackagePresent)
		fmt.Fprintf(b, "| build relevant | %s |\n", a.BuildRelevant)
		fmt.Fprintf(b, "| static call analysis (govulncheck) | %s |\n", govulncheckSummary(c, false))
		if len(a.CheckedModules) > 0 {
			fmt.Fprintf(b, "| modules probed | `%s` |\n", strings.Join(a.CheckedModules, "`, `"))
		}
		if a.SelectedModule != "" {
			fmt.Fprintf(b, "| selected module | `%s` |\n", a.SelectedModule)
		}
		if len(a.SelectedModules) > 0 {
			fmt.Fprintf(b, "| modules linked | `%s` |\n", strings.Join(a.SelectedModules, "`, `"))
		}
		if len(a.PendingModules) > 0 {
			fmt.Fprintf(b, "| modules version-unresolved | `%s` |\n", strings.Join(a.PendingModules, "`, `"))
		}
		if len(a.CheckedPackages) > 0 {
			fmt.Fprintf(b, "| packages probed | `%s` |\n", strings.Join(a.CheckedPackages, "`, `"))
		}
		if len(a.EvidenceIDs) > 0 {
			fmt.Fprintf(b, "| evidence | %s |\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
		}
		b.WriteString("\n")
	}
}

// renderAuditExploitModel prints the full exploit model: root cause (with
// alternatives, unverified and absent candidates), conditions with params,
// locus subjects, expert non-locus decisions, machine proposals and
// annotations, unresolved/absent subjects and validation records.
func renderAuditExploitModel(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if c.RootCause == nil && c.Exploit == nil && len(c.EvidenceGraph.Validations) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Первопричина, модель эксплуатации и локусы\n\n")
	} else {
		b.WriteString("## Root cause, exploit model and loci\n\n")
	}

	if c.RootCause != nil {
		if isRU {
			fmt.Fprintf(b, "### Первопричина дефекта: %s\n\n", rootCauseStatus(c.RootCause.Status, true))
		} else {
			fmt.Fprintf(b, "### Root cause: `%s`\n\n", c.RootCause.Status)
		}
		writeRootCauses(b, c.RootCause.RootCauses, isRU)
		if len(c.RootCause.Alternatives) > 0 {
			if isRU {
				b.WriteString("#### Альтернативные кандидаты\n\n")
			} else {
				b.WriteString("#### Alternative candidates\n\n")
			}
			writeRootCauses(b, c.RootCause.Alternatives, isRU)
		}
		if len(c.RootCause.Unverified) > 0 {
			if isRU {
				b.WriteString("#### Неподтверждённые кандидаты (в зоне анализа)\n\n")
			} else {
				b.WriteString("#### Unverified candidates (in scope)\n\n")
			}
			writeRootCauses(b, c.RootCause.Unverified, isRU)
		}
		if c.RootCause.FixDiff != "" {
			if isRU {
				fmt.Fprintf(b, "- Фиксирующий diff: %s\n\n", firstCommitLine(c.RootCause.FixDiff))
			} else {
				fmt.Fprintf(b, "- Fix diff: %s\n\n", firstCommitLine(c.RootCause.FixDiff))
			}
		}
	}

	if c.Exploit != nil {
		ex := c.Exploit
		if ex.Class != "" {
			if isRU {
				fmt.Fprintf(b, "Класс дефекта: `%s`\n\n", ex.Class)
			} else {
				fmt.Fprintf(b, "Defect class: `%s`\n\n", ex.Class)
			}
		}
		if ex.Impact != "" {
			if isRU {
				fmt.Fprintf(b, "Последствия: %s\n\n", ex.Impact)
			} else {
				fmt.Fprintf(b, "Impact: %s\n\n", ex.Impact)
			}
		}
		if ex.ProtocolRole != "" {
			if isRU {
				fmt.Fprintf(b, "Роль протокола: `%s`\n\n", ex.ProtocolRole)
			} else {
				fmt.Fprintf(b, "Protocol role: `%s`\n\n", ex.ProtocolRole)
			}
		}
		if len(ex.RootCauses) > 0 {
			if isRU {
				fmt.Fprintf(b, "- Сайты первопричины: `%s`\n", symbolRefsLine(ex.RootCauses))
			} else {
				fmt.Fprintf(b, "- Root-cause sites: `%s`\n", symbolRefsLine(ex.RootCauses))
			}
			b.WriteString("\n")
		}
		if isRU {
			writeConditions(b, "Обязательные условия (mandatory)", ex.MandatoryConditions, true)
			writeConditions(b, "Сопутствующие факторы (supporting)", ex.SupportingFactors, true)
		} else {
			writeConditions(b, "Mandatory conditions", ex.MandatoryConditions, false)
			writeConditions(b, "Supporting factors", ex.SupportingFactors, false)
		}
		if len(ex.LocusSubjects) > 0 {
			if isRU {
				fmt.Fprintf(b, "#### Состав локуса дефекта (LocusSubjects)\n\n- `%s`\n\n", symbolRefsLine(ex.LocusSubjects))
			} else {
				fmt.Fprintf(b, "#### Defect locus set (LocusSubjects)\n\n- `%s`\n\n", symbolRefsLine(ex.LocusSubjects))
			}
		}
		writeLocusDecisions(b, c.NonLocusBasis, "Решения эксперта о non-locus (уровень кейса)", "Expert non-locus decisions (case level)", isRU)
		writeLocusDecisions(b, ex.NonLocusBasis, "Решения эксперта о non-locus (модель)", "Expert non-locus decisions (model)", isRU)
		writeLocusDecisions(b, ex.ProposedNonLocus, "Машинные предложения non-locus (не приняты автоматически)", "Machine non-locus proposals (not auto-accepted)", isRU)
		writeLocusDecisions(b, ex.LocusAnnotations, "Аннотации локуса", "Locus annotations", isRU)
		if len(ex.UnresolvedSubjects) > 0 {
			if isRU {
				fmt.Fprintf(b, "#### Неразрешённые заявленные субъекты\n\n- `%s`\n\n", symbolRefsLine(ex.UnresolvedSubjects))
			} else {
				fmt.Fprintf(b, "#### Unresolved declared subjects\n\n- `%s`\n\n", symbolRefsLine(ex.UnresolvedSubjects))
			}
		}
		if len(ex.AbsentSubjects) > 0 {
			if isRU {
				fmt.Fprintf(b, "#### Субъекты, доказанно отсутствующие в сборке\n\n- `%s`\n\n", symbolRefsLine(ex.AbsentSubjects))
			} else {
				fmt.Fprintf(b, "#### Subjects proven absent from the build\n\n- `%s`\n\n", symbolRefsLine(ex.AbsentSubjects))
			}
		}
		if len(ex.EvidenceIDs) > 0 {
			fmt.Fprintf(b, "- **Evidence IDs:** %s\n\n", strings.Join(evidenceIDs(ex.EvidenceIDs), ", "))
		}
	}

	if vals := c.EvidenceGraph.Validations; len(vals) > 0 {
		if isRU {
			b.WriteString("### Записи валидации\n\n")
			b.WriteString("| Место | Свойство | Аргумент | Guard | Conditional | Покрывает | Границы |\n|---|---|---|---|---|---|---|\n")
		} else {
			b.WriteString("### Validation records\n\n")
			b.WriteString("| site | property | arg | guard | conditional | covers | bounds |\n|---|---|---|---|---|---|---|\n")
		}
		for _, v := range vals {
			covers := ""
			if v.Covers != nil {
				covers = p.location(v.Covers.File, "", v.Covers.Line).Text
			}
			bounds := ""
			if v.BoundLow != nil || v.BoundHigh != nil {
				lo, hi := "-∞", "+∞"
				if v.BoundLow != nil {
					lo = fmt.Sprintf("%d", *v.BoundLow)
				}
				if v.BoundHigh != nil {
					hi = fmt.Sprintf("%d", *v.BoundHigh)
				}
				bounds = fmt.Sprintf("[%s, %s]", lo, hi)
			}
			fmt.Fprintf(b, "| `%s` | %s | %d | %v | %v | `%s` | %s |\n",
				p.location(v.File, "", v.Line).Text,
				sanitizeTableString(v.Property, 60), v.Arg, v.Guard, v.Conditional, covers, bounds)
		}
		b.WriteString("\n")
	}
}

func writeRootCauses(b *strings.Builder, rcs []domain.RootCause, isRU bool) {
	for _, rc := range rcs {
		absent := ""
		if rc.Absent {
			if isRU {
				absent = " (пакет отсутствует в сборке)"
			} else {
				absent = " (package absent from build)"
			}
		}
		if isRU {
			fmt.Fprintf(b, "- `%s.%s` (%s) — %s%s\n", rc.Package, rc.Symbol,
				rootCauseRole(rc.Role, true), rootCauseMechanism(rc.Mechanism, true), absent)
		} else {
			fmt.Fprintf(b, "- `%s.%s` (%s) — %s%s\n", rc.Package, rc.Symbol,
				rootCauseRole(rc.Role, false), rootCauseMechanism(rc.Mechanism, false), absent)
		}
	}
	b.WriteString("\n")
}

func symbolRefsLine(syms []domain.SymbolRef) string {
	var names []string
	for _, s := range syms {
		names = append(names, s.Package+"."+s.Symbol)
	}
	return strings.Join(names, "`, `")
}

func writeLocusDecisions(b *strings.Builder, ds []domain.LocusDecision, titleRU, titleEN string, isRU bool) {
	if len(ds) == 0 {
		return
	}
	if isRU {
		fmt.Fprintf(b, "#### %s\n\n", titleRU)
	} else {
		fmt.Fprintf(b, "#### %s\n\n", titleEN)
	}
	for _, d := range ds {
		auth := d.Authority
		if auth == "" {
			auth = "-"
		}
		fmt.Fprintf(b, "- `%s.%s` — basis: %s; authority: `%s`\n",
			d.Symbol.Package, d.Symbol.Symbol, d.Basis, auth)
	}
	b.WriteString("\n")
}

// renderAuditClaims prints every claim with id, producer, result, falsifier,
// falsifier basis, negative-verification internals, limitations and
// evidence ids. VERIFIED (demoted) history is preserved.
func renderAuditClaims(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if len(c.Claims) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Условия эксплуатации и верификация\n\n")
		b.WriteString("| Claim | Условие | Производитель | Результат | Фалсификатор | Основание | Обоснование | Верификация | Доказательства |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	} else {
		b.WriteString("## Exploit conditions and verification\n\n")
		b.WriteString("| claim | condition | producer | result | falsifier | falsifier basis | explanation | verification | evidence |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	}
	for _, cl := range c.Claims {
		expl := localizeClaimExplanation(cl.Explanation, isRU)
		if expl == "" {
			expl = "—"
		}
		verif := claimVerification(cl, isRU)
		if verif == "" {
			verif = "—"
		}
		evs := strings.Join(evidenceIDs(cl.EvidenceIDs), ", ")
		if evs == "" {
			evs = "—"
		}
		id := string(cl.ID)
		if id == "" {
			id = "—"
		}
		producer := cl.Producer
		if producer == "" {
			producer = "—"
		}
		falsifier := cl.Falsifier
		if falsifier == "" {
			falsifier = "—"
		}
		fbasis := cl.FalsifierBasis
		if fbasis == "" {
			fbasis = "—"
		}
		fmt.Fprintf(b, "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
			id, cl.ConditionID, producer, localizeClaimResult(cl.Result, isRU),
			falsifier, fbasis, sanitizeTableString(p.text(expl), 140), verif, evs)
	}
	b.WriteString("\n")

	for _, cl := range c.Claims {
		nv := cl.NegativeVerification
		if nv == nil && len(cl.Limitations) == 0 {
			continue
		}
		if isRU {
			fmt.Fprintf(b, "- `%s` → `%s`:\n", cl.ID, cl.ConditionID)
		} else {
			fmt.Fprintf(b, "- `%s` → `%s`:\n", cl.ID, cl.ConditionID)
		}
		if nv != nil {
			if isRU {
				fmt.Fprintf(b, "  - negative verification: `%s`", nv.Status)
			} else {
				fmt.Fprintf(b, "  - negative verification: `%s`", nv.Status)
			}
			if nv.Notes != "" {
				fmt.Fprintf(b, " — %s", p.text(nv.Notes))
			}
			b.WriteString("\n")
			if len(nv.EvidenceIDs) > 0 {
				fmt.Fprintf(b, "    - evidence: %s\n", strings.Join(evidenceIDs(nv.EvidenceIDs), ", "))
			}
			for _, l := range nv.Limitations {
				fmt.Fprintf(b, "    - limitation: %s\n", p.text(l))
			}
		}
		for _, l := range cl.Limitations {
			fmt.Fprintf(b, "  - limitation: %s\n", p.text(l))
		}
	}
	b.WriteString("\n")
}

// renderAuditEvidence prints the full evidence register with ids, kinds,
// quality, source location, tool/version and artifact hash.
func renderAuditEvidence(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	evList := c.EvidenceGraph.EvidenceList()
	if len(evList) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Реестр доказательств\n\n")
		b.WriteString("| ID | Тип | Качество | Источник / инструмент | Суть |\n|---|---|---|---|---|\n")
	} else {
		b.WriteString("## Evidence register\n\n")
		b.WriteString("| id | kind | quality | source / tool | details |\n|---|---|---|---|---|\n")
	}
	for _, e := range evList {
		kindDesc := formatEvidenceKind(e.Kind, isRU)
		srcDesc := formatEvidenceSource(e, p, isRU)
		if e.ToolVersion != "" {
			srcDesc += " `" + e.ToolVersion + "`"
		}
		if e.ArtifactHash != "" {
			srcDesc += " sha256:`" + e.ArtifactHash + "`"
		}
		detail := formatEvidenceDetail(e, c, p, isRU)
		quality := string(e.Quality)
		if quality == "" {
			quality = "—"
		}
		fmt.Fprintf(b, "| `%s` | %s | %s | %s | %s |\n", e.ID, kindDesc, quality, srcDesc, detail)
		for _, l := range e.Limitations {
			fmt.Fprintf(b, "| | | | limitation | %s |\n", sanitizeTableString(p.text(l), 140))
		}
	}
	b.WriteString("\n")
}

// renderAuditExposures prints resolved exposure facts and the entrypoint
// inventory verbatim.
func renderAuditExposures(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	exps := c.EvidenceGraph.ExposuresList()
	eps := c.EvidenceGraph.Entrypoints
	if len(exps) == 0 && len(eps) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Факты сетевой экспозиции\n\n")
	} else {
		b.WriteString("## Network exposure facts\n\n")
	}
	if len(exps) > 0 {
		if isRU {
			b.WriteString("| Направление | Вид | Цель | Адрес | Источник адреса | Область | Владелец | Место |\n|---|---|---|---|---|---|---|---|\n")
		} else {
			b.WriteString("| direction | kind | target | address | address source | scope | owner | location |\n|---|---|---|---|---|---|---|---|\n")
		}
		for _, f := range exps {
			fmt.Fprintf(b, "| `%s` | `%s` | `%s` | `%s` | %s | %s | %s | `%s` |\n",
				f.Direction, f.Kind, sanitizeTableString(f.Target, 60), f.Address,
				localizeAddressSource(f.AddressSource, isRU), localizeExposureScope(f.Scope, isRU),
				f.Owner, p.location(f.File, "", f.Line).Text)
		}
		b.WriteString("\n")
	}
	if len(eps) > 0 {
		if isRU {
			b.WriteString("### Точки входа (entrypoints)\n\n")
		} else {
			b.WriteString("### Entrypoints\n\n")
		}
		for _, ep := range eps {
			fmt.Fprintf(b, "- `%s` `%s` kind=`%s` detail=`%s` exposed=%v\n",
				p.location(ep.File, "", ep.Line).Text, ep.Function, ep.Kind, sanitizeTableString(p.text(ep.Detail), 60), ep.Exposed)
		}
		b.WriteString("\n")
	}
}

// renderAuditDataFlows prints data flows and call paths with full detail:
// condition, source, transformations, sink, arg, origin, value and
// PayloadUnproven.
func renderAuditDataFlows(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	flows := c.EvidenceGraph.DataFlows
	paths := c.EvidenceGraph.CallPaths
	if len(flows) == 0 && len(paths) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Потоки данных\n\n")
	} else {
		b.WriteString("## Data flows\n\n")
	}
	if len(flows) > 0 {
		if isRU {
			b.WriteString("### Потоки данных\n\n")
			b.WriteString("| Условие | Источник | Трансформации | Приёмник | Арг | Происхождение | Значение | PayloadUnproven | Комментарий |\n|---|---|---|---|---|---|---|---|---|\n")
		} else {
			b.WriteString("### Data flows\n\n")
			b.WriteString("| condition | source | transformations | sink | arg | origin | value | payload_unproven | summary |\n|---|---|---|---|---|---|---|---|---|\n")
		}
		for _, f := range flows {
			var tx []string
			for _, t := range f.Transformations {
				name := t.Callee
				if name == "" {
					name = t.Function
				}
				tx = append(tx, name)
			}
			srcName := f.Source.Callee
			if srcName == "" {
				srcName = f.Source.Function
			}
			sinkName := f.Sink.Callee
			if sinkName == "" {
				sinkName = f.Sink.Function
			}
			val := "—"
			if f.Value != nil {
				val = fmt.Sprintf("%d", *f.Value)
			}
			cond := string(f.ConditionID)
			if cond == "" {
				cond = "—"
			}
			fmt.Fprintf(b, "| `%s` | `%s` `%s` | %s | `%s` `%s` | %d | `%s` | %s | %v | %s |\n",
				cond, srcName, p.location(f.Source.File, f.Source.Package, f.Source.Line).Text,
				sanitizeTableString(strings.Join(tx, " → "), 60),
				sinkName, p.location(f.Sink.File, f.Sink.Package, f.Sink.Line).Text,
				f.Arg, f.Origin, val, f.PayloadUnproven,
				sanitizeTableString(p.text(f.Summary), 80))
		}
		b.WriteString("\n")
	}
	if len(paths) > 0 {
		if isRU {
			b.WriteString("### Пути вызова (call paths)\n\n")
		} else {
			b.WriteString("### Call paths\n\n")
		}
		for i, cp := range paths {
			cond := string(cp.ConditionID)
			if cond == "" {
				cond = "—"
			}
			ev := string(cp.EvidenceID)
			if ev == "" {
				ev = "—"
			}
			fmt.Fprintf(b, "- path %d (condition `%s`, evidence `%s`):\n", i+1, cond, ev)
			for _, fr := range cp.Frames {
				fmt.Fprintf(b, "  - `%s.%s` (`%s`)\n", fr.Package, fr.Function, p.location(fr.File, fr.Package, fr.Line).Text)
			}
		}
		b.WriteString("\n")
	}
}

// renderAuditClosures prints the ingress- and sink-closure coverage
// inventories: completeness flag, blockers and every recorded item/site.
func renderAuditClosures(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	igs := c.EvidenceGraph.IngressClosures
	sks := c.EvidenceGraph.SinkClosures
	if len(igs) == 0 && len(sks) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Покрытие входов и дефектных операций\n\n")
	} else {
		b.WriteString("## Ingress and defect-operation coverage\n\n")
	}
	for _, cl := range igs {
		if isRU {
			fmt.Fprintf(b, "### Ingress-closure `%s` (модуль `%s`, complete=%v)\n\n", cl.ConditionID, cl.Module, cl.Complete)
		} else {
			fmt.Fprintf(b, "### Ingress closure `%s` (module `%s`, complete=%v)\n\n", cl.ConditionID, cl.Module, cl.Complete)
		}
		for _, it := range cl.Items {
			fmt.Fprintf(b, "- `%s` kind=`%s` callee=`%s` arg=%d origin=`%s` reaches=`%s` — %s\n",
				p.file(it.File, "").Text, it.Kind, it.Callee, it.Arg, it.Origin,
				strings.Join(it.Reaches, ","), sanitizeTableString(p.text(it.Detail), 80))
		}
		for _, bl := range cl.Blockers {
			if isRU {
				fmt.Fprintf(b, "- блокер: %s\n", bl)
			} else {
				fmt.Fprintf(b, "- blocker: %s\n", bl)
			}
		}
		b.WriteString("\n")
	}
	for _, cl := range sks {
		if isRU {
			fmt.Fprintf(b, "### Sink-closure `%s` (модуль `%s`, complete=%v)\n\n", cl.ConditionID, cl.Module, cl.Complete)
			if cl.Basis != "" {
				fmt.Fprintf(b, "- основание полноты: %s\n", cl.Basis)
			}
		} else {
			fmt.Fprintf(b, "### Sink closure `%s` (module `%s`, complete=%v)\n\n", cl.ConditionID, cl.Module, cl.Complete)
			if cl.Basis != "" {
				fmt.Fprintf(b, "- completeness basis: %s\n", cl.Basis)
			}
		}
		for _, s := range cl.Sites {
			fmt.Fprintf(b, "- sink `%s` `%s` arg=%d live=%v origin=`%s` — %s\n",
				s.Sink, p.location(s.File, "", s.Line).Text, s.Arg, s.Live, s.Origin, sanitizeTableString(p.text(s.Detail), 80))
		}
		for _, bl := range cl.Blockers {
			if isRU {
				fmt.Fprintf(b, "- блокер: %s\n", bl)
			} else {
				fmt.Fprintf(b, "- blocker: %s\n", bl)
			}
		}
		b.WriteString("\n")
	}
}

// renderAuditTools prints the tool execution journal with full (untruncated)
// stdout/stderr SHA-256 hashes.
func renderAuditTools(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	texs := c.EvidenceGraph.ToolExecutions
	if len(texs) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Журнал инструментов\n\n")
		b.WriteString("| ID | Инструмент | Аргументы | Каталог | Код возврата | Длительность (мс) | stdout sha256 | stderr sha256 | Ошибка |\n|---|---|---|---|---|---|---|---|---|\n")
	} else {
		b.WriteString("## Tool executions\n\n")
		b.WriteString("| id | tool | args | dir | exit | ms | stdout sha256 | stderr sha256 | error |\n|---|---|---|---|---|---|---|---|---|\n")
	}
	for _, t := range texs {
		tool := t.Tool
		if t.Version != "" {
			tool += "@" + t.Version
		}
		err := t.Error
		if err == "" {
			err = "—"
		}
		fmt.Fprintf(b, "| `%s` | `%s` | `%s` | `%s` | %d | %d | `%s` | `%s` | %s |\n",
			t.ID, tool, sanitizeTableString(strings.Join(t.Args, " "), 80), p.file(t.Dir, "").Text,
			t.ExitCode, t.DurationMs, t.StdoutSHA256, t.StderrSHA256, sanitizeTableString(p.text(err), 80))
	}
	b.WriteString("\n")
}

// renderAuditRuntime prints runtime evidence facts verbatim.
func renderAuditRuntime(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if len(c.EvidenceGraph.Runtime) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Факты среды\n\n")
	} else {
		b.WriteString("## Runtime facts\n\n")
	}
	for _, id := range c.EvidenceGraph.Runtime {
		if e := c.EvidenceGraph.EvidenceByID(id); e != nil {
			fmt.Fprintf(b, "- `%s` %s: %s\n", e.ID, e.Source, p.text(strings.TrimSpace(e.Content)))
		}
	}
	b.WriteString("\n")
}

// renderAuditBuildTest prints build/test evidence verbatim.
func renderAuditBuildTest(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	var bt []domain.Evidence
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceBuild || e.Kind == domain.EvidenceTest {
			bt = append(bt, e)
		}
	}
	if len(bt) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Сборка и тесты\n\n")
	} else {
		b.WriteString("## Build and tests\n\n")
	}
	for _, e := range bt {
		name := e.Command
		if name == "" {
			name = e.Source
		}
		fmt.Fprintf(b, "- `%s` (`%s`, %s):\n\n%s\n\n", e.ID, name, e.Kind, p.text(strings.TrimSpace(e.Content)))
	}
}

// renderAuditReviews prints review findings verbatim.
func renderAuditReviews(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if len(c.Reviews) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Рецензирование\n\n")
	} else {
		b.WriteString("## Reviews\n\n")
	}
	for _, rv := range c.Reviews {
		fmt.Fprintf(b, "- `%s` → **%s**", rv.ID, rv.Result)
		if len(rv.Findings) > 0 {
			b.WriteString("\n")
			for _, f := range rv.Findings {
				if f.TargetID != "" {
					fmt.Fprintf(b, "  - [%s] %s `%s`: %s", f.Severity, f.TargetType, f.TargetID, p.text(f.Problem))
					if f.RequiredCheck != "" {
						fmt.Fprintf(b, " (required check: %s)", f.RequiredCheck)
					}
					b.WriteString("\n")
				} else {
					fmt.Fprintf(b, "  - [%s] %s: %s\n", f.Severity, f.TargetType, p.text(f.Problem))
				}
			}
		} else {
			if isRU {
				b.WriteString(" — замечаний нет\n")
			} else {
				b.WriteString(" — no findings\n")
			}
		}
	}
	b.WriteString("\n")
}

// renderAuditHypotheses prints every working hypothesis verbatim.
func renderAuditHypotheses(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if len(c.Hypotheses) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Рабочие гипотезы\n\n")
	} else {
		b.WriteString("## Working hypotheses\n\n")
	}
	for _, h := range c.Hypotheses {
		fmt.Fprintf(b, "- `%s` `%s` → **%s**: %s", h.ID, h.ConditionID, h.Status, p.text(h.Statement))
		if len(h.ExpectedEvidence) > 0 {
			var kinds []string
			for _, k := range h.ExpectedEvidence {
				kinds = append(kinds, string(k))
			}
			fmt.Fprintf(b, " (expected: %s)", strings.Join(kinds, ", "))
		}
		if len(h.EvidenceIDs) > 0 {
			fmt.Fprintf(b, " (evidence: %s)", strings.Join(evidenceIDs(h.EvidenceIDs), ", "))
		}
		if h.Notes != "" {
			fmt.Fprintf(b, " — %s", p.text(h.Notes))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

// renderAuditAIArtifacts dumps the persisted AI artifacts completely:
// CVE analysis proposal with binding limits, source bundle, strategy plan,
// semantic review and the justification dossier.
func renderAuditAIArtifacts(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if c.CVEAnalysis == nil && c.StrategyPlan == nil && c.SemanticReview == nil &&
		c.Justification == nil && c.CVEAnalysisBundle == nil &&
		c.UsageSnapshot().LLMCalls == 0 && c.CVEAnalysisProfile == "" {
		return
	}
	if isRU {
		b.WriteString("## Артефакты AI-анализа\n\n")
	} else {
		b.WriteString("## AI analysis artifacts\n\n")
	}
	usage := c.UsageSnapshot()
	if isRU {
		fmt.Fprintf(b, "- Профиль: `%s`; LLM-вызовов: %d; strict-llm: %v\n\n",
			c.CVEAnalysisProfile, usage.LLMCalls, c.StrictLLM)
	} else {
		fmt.Fprintf(b, "- Profile: `%s`; LLM calls: %d; strict-llm: %v\n\n",
			c.CVEAnalysisProfile, usage.LLMCalls, c.StrictLLM)
	}

	if c.CVEAnalysis != nil {
		a := c.CVEAnalysis
		if isRU {
			fmt.Fprintf(b, "### Предложение анализа CVE (ревизия %d, уверенность %s)\n\n", a.Revision, a.Confidence)
		} else {
			fmt.Fprintf(b, "### CVE analysis proposal (revision %d, confidence %s)\n\n", a.Revision, a.Confidence)
		}
		fmt.Fprintf(b, "- id: `%s`; binding module: `%s` @ `%s` (advisory `%s`, hash `%s`)\n",
			a.ID, a.Binding.Module, a.Binding.ResolvedVersion, a.Binding.AdvisoryID, a.Binding.AdvisoryHash)
		if a.Binding.VulnerableSourceHash != "" {
			fmt.Fprintf(b, "- vulnerable source hash: `%s`\n", a.Binding.VulnerableSourceHash)
		}
		if a.Binding.FixManifestHash != "" {
			fmt.Fprintf(b, "- fix manifest hash: `%s`\n", a.Binding.FixManifestHash)
		}
		fmt.Fprintf(b, "- tool iterations: %d\n", a.ToolIterations)
		for _, m := range a.Mechanisms {
			fmt.Fprintf(b, "- `%s`: %s\n  - faulting sites: `%s`\n", m.ID, p.text(m.Summary), strings.Join(m.FaultingSites, "`, `"))
			if len(m.AuxiliarySites) > 0 {
				fmt.Fprintf(b, "  - auxiliary sites: `%s`\n", strings.Join(m.AuxiliarySites, "`, `"))
			}
			if m.PatchExplanation != "" {
				fmt.Fprintf(b, "  - patch explanation: %s\n", p.text(m.PatchExplanation))
			}
		}
		for _, pre := range a.Preconditions {
			fmt.Fprintf(b, "- precondition: %s\n", p.text(pre))
		}
		if len(a.EvidenceIDs) > 0 {
			fmt.Fprintf(b, "- evidence: %s\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
		}
		b.WriteString("\n")
	}

	if c.CVEAnalysisBundle != nil {
		bd := c.CVEAnalysisBundle
		if isRU {
			fmt.Fprintf(b, "### Пакет исходников CVE (manifest: `%s`)\n\n", bd.ManifestStatus)
		} else {
			fmt.Fprintf(b, "### CVE source bundle (manifest: `%s`)\n\n", bd.ManifestStatus)
		}
		for _, art := range bd.Artifacts {
			fmt.Fprintf(b, "- `%s` (%s) `%s` status=`%s` hash=`%s` evidence=`%s`\n",
				art.ID, art.Side, p.text(art.URI), art.Status, art.Hash, art.EvidenceID)
			for _, l := range art.Limitations {
				fmt.Fprintf(b, "  - limitation: %s\n", p.text(l))
			}
		}
		if bd.SourceDir != "" {
			fmt.Fprintf(b, "- source dir: `%s`\n", p.text(bd.SourceDir))
		}
		for _, l := range bd.Limitations {
			fmt.Fprintf(b, "- limitation: %s\n", p.text(l))
		}
		b.WriteString("\n")
	}

	if c.StrategyPlan != nil {
		sp := c.StrategyPlan
		if isRU {
			fmt.Fprintf(b, "### План стратегии `%s`\n\n", sp.ID)
			fmt.Fprintf(b, "- выбранная стратегия: `%s`\n", sp.SelectedStrategy)
		} else {
			fmt.Fprintf(b, "### Strategy plan `%s`\n\n", sp.ID)
			fmt.Fprintf(b, "- selected strategy: `%s`\n", sp.SelectedStrategy)
		}
		for _, o := range sp.Obligations {
			fmt.Fprintf(b, "  - %s\n", p.text(o))
		}
		if sp.StopReason != "" {
			fmt.Fprintf(b, "- stop reason: %s\n", p.text(sp.StopReason))
		}
		b.WriteString("\n")
	}

	if c.SemanticReview != nil {
		sr := c.SemanticReview
		if isRU {
			fmt.Fprintf(b, "### Семантическое ревью (passed=%v, reviewer `%s`)\n\n", sr.Passed, sr.Reviewer)
		} else {
			fmt.Fprintf(b, "### Semantic review (passed=%v, reviewer `%s`)\n\n", sr.Passed, sr.Reviewer)
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(b, "- %s\n", p.text(f))
		}
		if len(sr.EvidenceIDs) > 0 {
			fmt.Fprintf(b, "- evidence: %s\n", strings.Join(evidenceIDs(sr.EvidenceIDs), ", "))
		}
		b.WriteString("\n")
	}

	if c.Justification != nil {
		j := c.Justification
		if isRU {
			b.WriteString("### Досье обоснования (justification)\n\n")
			fmt.Fprintf(b, "- вердикт досье: `%s`\n", j.Verdict)
		} else {
			b.WriteString("### Justification dossier\n\n")
			fmt.Fprintf(b, "- dossier verdict: `%s`\n", j.Verdict)
		}
		if j.ExecutiveSummary != "" {
			fmt.Fprintf(b, "- executive summary: %s\n", p.text(j.ExecutiveSummary))
		}
		if j.TechnicalMechanism != "" {
			fmt.Fprintf(b, "- technical mechanism: %s\n", p.text(j.TechnicalMechanism))
		}
		if len(j.ProductExposure.EntrypointConstructors) > 0 {
			fmt.Fprintf(b, "- entrypoint constructors: `%s`\n", strings.Join(j.ProductExposure.EntrypointConstructors, "`, `"))
		}
		if len(j.ProductExposure.AbsentConstructors) > 0 {
			fmt.Fprintf(b, "- absent constructors: `%s`\n", strings.Join(j.ProductExposure.AbsentConstructors, "`, `"))
		}
		if len(j.ProductExposure.LinkedPackages) > 0 {
			fmt.Fprintf(b, "- linked packages: `%s`\n", strings.Join(j.ProductExposure.LinkedPackages, "`, `"))
		}
		if len(j.ProductExposure.UnlinkedPackages) > 0 {
			fmt.Fprintf(b, "- unlinked packages: `%s`\n", strings.Join(j.ProductExposure.UnlinkedPackages, "`, `"))
		}
		for _, vf := range j.VerifiedFacts {
			fmt.Fprintf(b, "- verified fact: %s\n", p.text(vf))
		}
		for _, rem := range j.HumanRemainder {
			fmt.Fprintf(b, "- human remainder `%s`: %s (evidence: %s)\n", rem.Obligation, p.text(rem.Question), rem.EvidenceRef)
		}
		if j.TrackerCommentRu != "" {
			fmt.Fprintf(b, "\n```\n%s\n```\n", p.text(strings.TrimSpace(j.TrackerCommentRu)))
		}
		b.WriteString("\n")
	}
}

// renderAuditMachineAssessment prints the internal machine disposition
// proposal — advisory only, explicitly marked as not changing the verdict.
func renderAuditMachineAssessment(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if c.Exploit == nil || len(c.Exploit.LocusSubjects) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Внутренние машинные гипотезы\n\n")
		b.WriteString("> ⚠️ Это внутренняя оценка анализатора для эксперта: она не является вердиктом и не изменяет финальный вердикт.\n\n")
	} else {
		b.WriteString("## Internal machine hypotheses\n\n")
		b.WriteString("> ⚠️ This is the analyzer's internal advisory for the expert: it is not the verdict and does not change the final verdict.\n\n")
	}
	b.WriteString(p.text(machineAssessment(c, isRU)))
	b.WriteString("\n")
}

// renderAuditProfiles prints both internal perimeter evaluations verbatim:
// verdict, reason, falsifier, priority and SLA, with non-actual profiles
// explicitly marked hypothetical. No user-action column.
func renderAuditProfiles(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if len(c.Profiles) == 0 {
		return
	}
	detPerimeter := c.DetectedPerimeter
	if detPerimeter == "" {
		detPerimeter = domain.PerimeterUnknown
	}
	detRationale := c.PerimeterRationale
	if detRationale == "" {
		detRationale = "-"
	}
	if isRU {
		b.WriteString("## Внутренние профили периметра\n\n")
		fmt.Fprintf(b, "- **Обнаруженный периметр развёртывания:** `%s`\n", localizePerimeter(detPerimeter, true))
		fmt.Fprintf(b, "- **Обоснование периметра:** %s\n\n", localizePerimeterRationale(detRationale, true))
		b.WriteString("| Сетевой контур | Модель угроз | Оценка | Приоритет | SLA | Основание | Фалсификатор | Статус среды |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, prof := range c.Profiles {
			contour, model := profileContourAndModel(prof, true)
			icon := verdictBadge(prof.Verdict)
			env := "фактическая"
			if !prof.IsTargetActual {
				env = "гипотетическая — не вердикт для текущей среды"
			}
			fmt.Fprintf(b, "| **%s** | %s | %s `%s` | `%s` | `%s` | %s | `%s` | %s |\n",
				contour, model, icon, prof.Verdict, prof.Priority, prof.SLA,
				sanitizeTableString(localizeVerdictReason(p.text(prof.Reason), true), 100), prof.Falsifier, env)
		}
		b.WriteString("\nГипотетические строки — внутренние оценки для альтернативных сред; они не являются вердиктом для текущей среды.\n\n")
	} else {
		b.WriteString("## Internal perimeter profiles\n\n")
		fmt.Fprintf(b, "- **Detected deployment perimeter:** `%s`\n", detPerimeter)
		fmt.Fprintf(b, "- **Perimeter rationale:** %s\n\n", detRationale)
		b.WriteString("| Perimeter | Threat model | Assessment | Priority | SLA | Reason | Falsifier | Environment |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, prof := range c.Profiles {
			contour, model := profileContourAndModel(prof, false)
			icon := verdictBadge(prof.Verdict)
			env := "actual"
			if !prof.IsTargetActual {
				env = "hypothetical — not a verdict for the current environment"
			}
			fmt.Fprintf(b, "| **%s** | %s | %s `%s` | `%s` | `%s` | %s | `%s` | %s |\n",
				contour, model, icon, prof.Verdict, prof.Priority, prof.SLA,
				sanitizeTableString(p.text(prof.Reason), 100), prof.Falsifier, env)
		}
		b.WriteString("\nHypothetical rows are internal evaluations for alternative environments; they are not verdicts for the current one.\n\n")
	}
}

// renderAuditLimitations prints the complete deduplicated limitation set.
func renderAuditLimitations(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	lims := allLimitations(c)
	if len(lims) == 0 {
		return
	}
	if isRU {
		b.WriteString("## Полный список ограничений\n\n")
	} else {
		b.WriteString("## Complete limitations list\n\n")
	}
	for _, l := range lims {
		fmt.Fprintf(b, "- %s\n", p.text(l))
	}
	b.WriteString("\n")
}

func rootCauseRole(role domain.RootCauseRole, isRU bool) string {
	if !isRU {
		return string(role)
	}
	switch role {
	case domain.RootCauseSink:
		return "Точка сбоя / Sink"
	case domain.RootCauseEntrypoint:
		return "Точка входа / Entrypoint"
	case domain.RootCausePropagation:
		return "Распространение / Propagation"
	default:
		return string(role)
	}
}

func rootCauseStatus(status domain.RootCauseStatus, isRU bool) string {
	if !isRU {
		return fmt.Sprintf("`%s`", status)
	}
	switch status {
	case domain.RootCauseResolved:
		return "Определена"
	case domain.RootCauseAmbiguous:
		return "Неоднозначно"
	case domain.RootCauseNotFound:
		return "Не найдена"
	default:
		return fmt.Sprintf("`%s`", status)
	}
}

func localizeAffectedBool(r domain.ClaimResult, isRU bool) string {
	if !isRU {
		return string(r)
	}
	switch r {
	case domain.ClaimTrue:
		return "Да"
	case domain.ClaimFalse:
		return "Нет"
	case domain.ClaimUnknown:
		return "Не определено"
	default:
		if strings.EqualFold(string(r), "true") {
			return "Да"
		}
		if strings.EqualFold(string(r), "false") {
			return "Нет"
		}
		return string(r)
	}
}

func localizeClaimResult(r domain.ClaimResult, isRU bool) string {
	if !isRU {
		return string(r)
	}
	switch r {
	case domain.ClaimTrue:
		return "Подтверждено (TRUE)"
	case domain.ClaimFalse:
		return "Опровергнуто (FALSE)"
	case domain.ClaimUnknown:
		return "Не определено (UNKNOWN)"
	default:
		if strings.EqualFold(string(r), "true") {
			return "Подтверждено (TRUE)"
		}
		if strings.EqualFold(string(r), "false") {
			return "Опровергнуто (FALSE)"
		}
		return string(r)
	}
}

func localizeAddressSource(src string, isRU bool) string {
	if !isRU {
		return src
	}
	switch src {
	case "literal":
		return "литерал"
	case "const":
		return "константа"
	case "config":
		return "конфигурация"
	case "param":
		return "параметр функции"
	case "dynamic":
		return "динамический"
	default:
		if strings.HasPrefix(src, "env:") {
			return "переменная окружения " + strings.TrimPrefix(src, "env:")
		}
		if strings.HasPrefix(src, "flag:") {
			return "флаг " + strings.TrimPrefix(src, "flag:")
		}
		return src
	}
}

func localizeExposureScope(scope string, isRU bool) string {
	if !isRU {
		return scope
	}
	switch scope {
	case "all-interfaces":
		return "все интерфейсы (0.0.0.0)"
	case "loopback":
		return "локальный интерфейс (127.0.0.1)"
	case "static":
		return "статический адрес"
	case "configured":
		return "настроен оператором (configured)"
	case "cluster-internal":
		return "внутрикластерный"
	case "public":
		return "публичный"
	default:
		return scope
	}
}

func govulncheckSummary(c *domain.AnalysisCase, isRU bool) string {
	if len(c.EvidenceGraph.CallPaths) > 0 {
		if isRU {
			return fmt.Sprintf("Обнаружены пути вызова к уязвимому коду (%d)", len(c.EvidenceGraph.CallPaths))
		}
		return fmt.Sprintf("Call path(s) to vulnerable code detected (%d)", len(c.EvidenceGraph.CallPaths))
	}
	if isRU {
		return "Трасса вызовов от кода продукта не обнаружена (чисто)"
	}
	return "No call path from product code found (clean)"
}

func hasMissingCall(c *domain.AnalysisCase) bool {
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.ID == "EV-MISSING-CALL" || strings.HasPrefix(string(e.ID), "EV-MISSING-CALL") {
			return true
		}
	}
	return false
}

func writeConditions(b *strings.Builder, title string, conds []domain.Condition, isRU bool) {
	if len(conds) == 0 {
		return
	}
	fmt.Fprintf(b, "#### %s\n\n", title)
	for _, cond := range conds {
		desc := localizeConditionDesc(string(cond.ID), cond.Description, isRU)
		mandatory := ""
		if cond.Mandatory {
			if isRU {
				mandatory = " (обязательное)"
			} else {
				mandatory = " (mandatory)"
			}
		}
		fmt.Fprintf(b, "- `%s` [%s]%s: %s%s\n", cond.ID, cond.Kind, mandatory, desc, renderParams(cond.Params))
		if len(cond.Subjects) > 0 {
			fmt.Fprintf(b, "  - subjects: `%s`\n", symbolRefsLine(cond.Subjects))
		}
		if cond.Subject != nil {
			fmt.Fprintf(b, "  - subject: `%s.%s`\n", cond.Subject.Package, cond.Subject.Symbol)
		}
	}
	b.WriteString("\n")
}

func renderParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return " {" + strings.Join(parts, ", ") + "}"
}

// claimVerification renders the falsifier/NV status so a claim that was
// proven and then demoted by review stays auditable in the table —
// e.g. "guards / VERIFIED (demoted)" instead of a bare UNKNOWN.
func claimVerification(cl domain.Claim, isRU bool) string {
	if cl.NegativeVerification == nil && cl.Falsifier == "" {
		return ""
	}
	var s string
	if cl.Falsifier != "" {
		f := string(cl.Falsifier)
		if isRU {
			switch cl.Falsifier {
			case "locus-package-absent":
				f = "Пакет отсутствует в сборке"
			case "trusted-infrastructure":
				f = "Доверенная инфраструктура"
			}
		}
		s = f
	}
	if cl.NegativeVerification != nil {
		st := string(cl.NegativeVerification.Status)
		if isRU {
			switch cl.NegativeVerification.Status {
			case domain.NegativeVerified:
				st = "ПОДТВЕРЖДЕНО"
			case domain.NegativeInsufficientScope:
				st = "Недостаточный охват"
			}
		}
		if s != "" {
			s += " / "
		}
		s += st
	}
	if cl.Result == domain.ClaimUnknown && cl.NegativeVerification != nil &&
		cl.NegativeVerification.Status == domain.NegativeVerified {
		if isRU {
			s += " (демотировано)"
		} else {
			s += " (demoted)"
		}
	}
	return s
}

func evidenceIDs(ids []domain.EvidenceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// machineAssessment renders the case-level machine opinion: a proposed
// disposition for the defect-locus falsifier, the expert decisions it
// depends on, and the assumptions outside machine verification. The
// package-absent falsifier needs every locus subject in a linked package
// to carry a recorded expert exclusion — so the block lists, per declared
// symbol, its package status and what the expert still has to decide.
// Advisory text for review — never part of the verdict.
func machineAssessment(c *domain.AnalysisCase, isRUOpt ...bool) string {
	isRU := len(isRUOpt) == 0 || isRUOpt[0]
	if c.Exploit == nil || len(c.Exploit.LocusSubjects) == 0 {
		return ""
	}
	if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
		if isRU {
			return "**Статус:** Уязвимость подтверждена и эксплуатируема: подтверждены пути вызова и передача внешних данных в уязвимый код. Автоматическое отклонение по составу пакетов неприменимо.\n"
		}
		return "**Status:** Vulnerability is confirmed exploitable: verified reachability and untrusted input paths reach the defect locus. Automated package-absence dismissal is not applicable.\n"
	}
	proposed := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.ProposedNonLocus {
		proposed[d.Symbol] = d
	}
	annotated := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.LocusAnnotations {
		annotated[d.Symbol] = d
	}

	var set map[string]bool
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidencePackageList {
			continue
		}
		if s, err := affected.PackageImportPaths([]byte(e.Content)); err == nil {
			set = s
		}
		break
	}
	if set == nil {
		if isRU {
			return "Оценку по отсутствию пакетов выставить нельзя: нет данных о составе сборки (`go list -deps`).\n"
		}
		return "Package-absence assessment unavailable: no build graph data (`go list -deps`).\n"
	}

	var b strings.Builder
	if isRU {
		b.WriteString("Отклонить уязвимость из-за отсутствия пакетов в сборке можно только при условии, что для каждой функции из advisory в *попавших в сборку* пакетах подтверждено решение о безопасности (код не содержит дефекта и признан безопасным):\n\n")
	} else {
		b.WriteString("Dismissal via package absence requires every advisory symbol in *compiled* packages to carry a confirmed safety decision (code lacks defect):\n\n")
	}
	var pending, proposedN, flagged int
	for _, s := range c.Exploit.LocusSubjects {
		name := "`" + s.Package + "." + s.Symbol + "`"
		if !set[s.Package] {
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет **отсутствует в сборке** (`go list -deps`) — код физически не скомпилирован\n", name)
			} else {
				fmt.Fprintf(&b, "- %s — package **absent from build** (`go list -deps`) — code not compiled\n", name)
			}
			continue
		}
		pending++
		if d, ok := proposed[s]; ok {
			proposedN++
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет входит в сборку — **рекомендуется исключить** (код безопасен): %s\n", name, d.Basis)
			} else {
				fmt.Fprintf(&b, "- %s — package included in build — **exclusion recommended** (code safe): %s\n", name, d.Basis)
			}
			continue
		}
		if d, ok := annotated[s]; ok {
			flagged++
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет входит в сборку — **исключение не рекомендуется**: %s — чтобы отклонить, эксперт должен опровергнуть этот вывод\n", name, d.Basis)
			} else {
				fmt.Fprintf(&b, "- %s — package included in build — **exclusion not recommended**: %s — to dismiss, an expert must refute this finding\n", name, d.Basis)
			}
		} else {
			if isRU {
				fmt.Fprintf(&b, "- %s — пакет входит в сборку — **требуется решение эксперта** (автоматический анализ не дал результатов)\n", name)
			} else {
				fmt.Fprintf(&b, "- %s — package included in build — **expert decision required** (automated analysis inconclusive)\n", name)
			}
		}
	}
	b.WriteString("\n")
	switch {
	case pending == 0:
		if isRU {
			b.WriteString("**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ** — ни один из пакетов с уязвимым кодом не входит в граф сборки приложения.\n")
		} else {
			b.WriteString("**Proposed disposition: DISMISSIBLE** — none of the packages with vulnerable code are included in the build graph.\n")
		}
	case flagged == 0 && pending == proposedN:
		if isRU {
			fmt.Fprintf(&b,
				"**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ ПОСЛЕ ПОДТВЕРЖДЕНИЯ** — подтвердите %d рекомендаций об исключении как безопасных; остальные пакеты в сборку не входят → вердикт `NO_EXPLOIT_PATH_FOUND` (для автоматического применения рекомендаций используйте флаг `--accept-locus-proposals`).\n",
				pending)
		} else {
			fmt.Fprintf(&b,
				"**Proposed disposition: DISMISSIBLE PENDING APPROVAL** — approve %d safety exclusion recommendations; remaining packages are absent from build → verdict `NO_EXPLOIT_PATH_FOUND` (use `--accept-locus-proposals` for automatic approval).\n",
				pending)
		}
	case flagged == 0:
		if isRU {
			fmt.Fprintf(&b,
				"**Предлагаемая оценка: ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)** — чтобы отклонить уязвимость, необходимо подтвердить решение о безопасности по всем %d функциям в попавших в сборку пакетах (%d рекомендованы к исключению; по %d автоматических данных нет).\n",
				pending, proposedN, pending-proposedN)
		} else {
			fmt.Fprintf(&b,
				"**Proposed disposition: CONDITIONAL REVIEW** — dismissing requires safety approval for all %d functions in linked packages (%d recommended for exclusion; %d lack automated evidence).\n",
				pending, proposedN, pending-proposedN)
		}
	default:
		if isRU {
			fmt.Fprintf(&b,
				"**Предлагаемая оценка: ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)** — чтобы отклонить уязвимость, необходимо подтвердить решение о безопасности по всем %d функциям в попавших в сборку пакетах (%d рекомендованы к исключению; для %d найдены признаки уязвимости, требующие проверки экспертом).\n",
				pending, proposedN, flagged)
		} else {
			fmt.Fprintf(&b,
				"**Proposed disposition: CONDITIONAL REVIEW** — dismissing requires safety approval for all %d functions in linked packages (%d recommended for exclusion; %d show vulnerability signs requiring expert review).\n",
				pending, proposedN, flagged)
		}
	}
	if isRU {
		b.WriteString("\nДопущения (не проверяются автоматически, эксперт подтверждает их при согласовании):\n")
		b.WriteString("- Список уязвимых функций в базе (advisory) полон (если уязвимость затрагивает другие функции библиотеки, анализ их не увидит)\n")
		b.WriteString("- Внесённые решения о безопасности верны (система проверяет факт их наличия, а не правильность)\n")
	} else {
		b.WriteString("\nAssumptions (not checked automatically, confirmed by expert on review):\n")
		b.WriteString("- Advisory vulnerable symbol list is complete (if vulnerability affects other functions, analysis will not see them)\n")
		b.WriteString("- Recorded safety decisions are correct (the system checks presence, not correctness)\n")
	}
	goos, goarch := c.Product.GOOS, c.Product.GOARCH
	if goos == "" {
		goos = "?"
	}
	if goarch == "" {
		goarch = "?"
	}
	tags := strings.Join(c.Product.BuildTags, ", ")
	if tags == "" {
		if isRU {
			tags = "не указаны"
		} else {
			tags = "none"
		}
	}
	if isRU {
		fmt.Fprintf(&b, "- Параметры сборки (%s/%s, теги: %s) соответствуют целевому окружению развёртывания\n",
			goos, goarch, tags)
	} else {
		fmt.Fprintf(&b, "- Build parameters (%s/%s, tags: %s) match the target deployment environment\n",
			goos, goarch, tags)
	}
	return b.String()
}

// allLimitations collects every recorded limitation across the case:
// affected/root-cause records, the evidence graph, verdict limitations,
// claim and negative-verification limitations, evidence limitations and
// the CVE source bundle — deduplicated, first-seen order.
func allLimitations(c *domain.AnalysisCase) []string {
	var out []string
	add := func(l string) {
		for _, x := range out {
			if x == l {
				return
			}
		}
		out = append(out, l)
	}
	if c.Affected != nil {
		for _, l := range c.Affected.Limitations {
			add(l)
		}
	}
	if c.RootCause != nil {
		for _, l := range c.RootCause.Limitations {
			add(l)
		}
	}
	// The verdict copies graph limitations into its own record — dedupe,
	// or every limitation prints twice.
	for _, l := range c.EvidenceGraph.Limitations {
		add(l)
	}
	for _, l := range c.EvidenceGraph.ToolLimitations {
		add(l)
	}
	if c.Verdict != nil {
		for _, l := range c.Verdict.Limitations {
			add(l)
		}
	}
	for _, cl := range c.Claims {
		for _, l := range cl.Limitations {
			add(l)
		}
		if cl.NegativeVerification != nil {
			for _, l := range cl.NegativeVerification.Limitations {
				add(l)
			}
		}
	}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		for _, l := range e.Limitations {
			add(l)
		}
	}
	if c.CVEAnalysisBundle != nil {
		for _, l := range c.CVEAnalysisBundle.Limitations {
			add(l)
		}
		for _, a := range c.CVEAnalysisBundle.Artifacts {
			for _, l := range a.Limitations {
				add(l)
			}
		}
	}
	return out
}

func linkedPackages(c *domain.AnalysisCase) map[string]bool {
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidencePackageList {
			if s, err := affected.PackageImportPaths([]byte(e.Content)); err == nil {
				return s
			}
		}
	}
	return nil
}

type locusSymbolNote struct {
	Symbol domain.SymbolRef
	Basis  string
}

// splitAdvisoryPackages partitions advisory-declared packages by presence in
// the build graph; presentNotes carries only recorded expert non-locus
// decisions (machine proposals are not presented as established safety).
func splitAdvisoryPackages(c *domain.AnalysisCase) (absentPkgs, presentPkgs []string, presentNotes []locusSymbolNote) {
	linked := linkedPackages(c)
	advisoryPkgs := map[string]bool{}

	if c.Exploit != nil {
		for _, s := range c.Exploit.LocusSubjects {
			advisoryPkgs[s.Package] = true
		}
	}
	for _, ap := range c.Vulnerability.AffectedPackages {
		if ap.Path != "" {
			advisoryPkgs[ap.Path] = true
		}
	}

	for pkg := range advisoryPkgs {
		if linked != nil {
			if !linked[pkg] {
				absentPkgs = append(absentPkgs, pkg)
			} else {
				presentPkgs = append(presentPkgs, pkg)
			}
		}
	}
	sort.Strings(absentPkgs)
	sort.Strings(presentPkgs)

	seenSym := map[domain.SymbolRef]bool{}
	if c.Exploit != nil {
		for _, d := range c.Exploit.NonLocusBasis {
			if linked != nil && linked[d.Symbol.Package] && !seenSym[d.Symbol] {
				seenSym[d.Symbol] = true
				presentNotes = append(presentNotes, locusSymbolNote{Symbol: d.Symbol, Basis: d.Basis})
			}
		}
	}
	return absentPkgs, presentPkgs, presentNotes
}

func profileContourAndModel(p domain.ProfileVerdict, isRU bool) (string, string) {
	switch p.Profile {
	case domain.ProfileClusterPerimeter:
		if isRU {
			return "Внутренний кластер / Mesh", "Доверенная инфраструктура"
		}
		return "Internal Cluster / Mesh", "Trusted Infrastructure"
	case domain.ProfileZeroTrust:
		if isRU {
			return "Публичный интернет", "Zero Trust / Hostile Peer"
		}
		return "Public Internet", "Zero Trust / Hostile Peer"
	default:
		name := string(p.Profile)
		if p.Title != "" {
			name = p.Title
		}
		return name, string(p.Profile)
	}
}

func formatEvidenceKind(k domain.EvidenceKind, isRU bool) string {
	if !isRU {
		switch k {
		case domain.EvidenceGovulncheck:
			return "Call Graph (govulncheck)"
		case domain.EvidenceModuleGraph:
			return "Module Graph (go.mod)"
		case domain.EvidencePackageList:
			return "Package Graph (deps)"
		case domain.EvidenceSourceSnippet:
			return "Source Snippet (AST)"
		case domain.EvidenceCallPath:
			return "Call Path"
		case domain.EvidenceDataFlow:
			return "Data Flow"
		case domain.EvidenceConfiguration:
			return "Network / Config"
		case domain.EvidenceEntrypoint:
			return "Entrypoint"
		case domain.EvidenceSearchResult:
			return "Symbol / Config"
		case domain.EvidenceAdvisory:
			return "Security Advisory"
		case domain.EvidenceFixDiff:
			return "Fix Patch (Diff)"
		case domain.EvidenceRuntime:
			return "Runtime Environment"
		default:
			return string(k)
		}
	}
	switch k {
	case domain.EvidenceGovulncheck:
		return "Анализ вызовов (govulncheck)"
	case domain.EvidenceModuleGraph:
		return "Граф модулей (go.mod)"
	case domain.EvidencePackageList:
		return "Граф пакетов сборки"
	case domain.EvidenceSourceSnippet:
		return "Исходный код (AST)"
	case domain.EvidenceCallPath:
		return "Путь вызова"
	case domain.EvidenceDataFlow:
		return "Поток данных (Taint/Flow)"
	case domain.EvidenceConfiguration:
		return "Сетевая конфигурация"
	case domain.EvidenceEntrypoint:
		return "Точка входа"
	case domain.EvidenceSearchResult:
		return "Символ / Конфиг"
	case domain.EvidenceAdvisory:
		return "База уязвимостей (Advisory)"
	case domain.EvidenceFixDiff:
		return "Патч исправления (Diff)"
	case domain.EvidenceRuntime:
		return "Среда выполнения"
	default:
		return string(k)
	}
}

func formatEvidenceSource(e domain.Evidence, p reportPaths, isRU bool) string {
	if e.File != "" {
		return fmt.Sprintf("`%s`", p.location(e.File, "", e.StartLine).Text)
	}
	if e.Command != "" {
		return fmt.Sprintf("`%s`", sanitizeTableString(p.text(e.Command), 40))
	}
	if e.Tool != "" {
		return fmt.Sprintf("`%s`", sanitizeTableString(e.Tool, 35))
	}
	if e.Source != "" {
		return sanitizeTableString(p.text(e.Source), 40)
	}
	return "-"
}

func formatEvidenceDetail(e domain.Evidence, c *domain.AnalysisCase, p reportPaths, isRU bool) string {
	if e.Kind == domain.EvidenceGovulncheck {
		var matched *domain.CallPath
		for i := range c.EvidenceGraph.CallPaths {
			if c.EvidenceGraph.CallPaths[i].EvidenceID == e.ID {
				matched = &c.EvidenceGraph.CallPaths[i]
				break
			}
		}
		if matched != nil && len(matched.Frames) > 0 {
			first := matched.Frames[0].Function
			last := matched.Frames[len(matched.Frames)-1].Function
			if isRU {
				return fmt.Sprintf("Трасса вызова (%d кадров): `%s` → ... → `%s`", len(matched.Frames), first, last)
			}
			return fmt.Sprintf("Call path (%d frames): `%s` → ... → `%s`", len(matched.Frames), first, last)
		}
		if isRU {
			return "Статический анализ govulncheck: трасса вызова к уязвимым функциям"
		}
		return "govulncheck static analysis: call path to affected symbols"
	}

	if e.Kind == domain.EvidenceModuleGraph {
		if isRU {
			return "Список зависимостей проекта и зафиксированных версий (go list -m)"
		}
		return "Project dependency list and resolved versions (go list -m)"
	}

	if e.Kind == domain.EvidencePackageList {
		if isRU {
			return "Граф пакетов, скомпилированных в приложение (go list -deps)"
		}
		return "Compiled package graph linked into application (go list -deps)"
	}

	if e.Kind == domain.EvidenceAdvisory {
		if isRU {
			return "Уязвимые функции и пакеты из advisory: " + sanitizeTableString(p.text(e.Content), 75)
		}
		return "Advisory declared affected symbols/packages: " + sanitizeTableString(p.text(e.Content), 75)
	}

	if e.Kind == domain.EvidenceFixDiff {
		firstLine := firstCommitLine(e.Content)
		if isRU {
			return "Коммит исправления: " + sanitizeTableString(firstLine, 80)
		}
		return "Upstream fix commit: " + sanitizeTableString(firstLine, 80)
	}

	if e.Kind == domain.EvidenceRuntime {
		if isRU {
			return "Параметры среды: " + sanitizeTableString(p.text(e.Content), 80)
		}
		return "Runtime parameters: " + sanitizeTableString(p.text(e.Content), 80)
	}

	if e.Kind == domain.EvidenceConfiguration {
		if isRU {
			return "Конфигурация сети / портов: " + sanitizeTableString(p.text(e.Content), 80)
		}
		return "Network / port configuration: " + sanitizeTableString(p.text(e.Content), 80)
	}

	if e.Kind == domain.EvidenceSourceSnippet {
		clean := sanitizeTableString(p.text(e.Content), 80)
		if isRU {
			return "Фрагмент кода: `" + clean + "`"
		}
		return "Code snippet: `" + clean + "`"
	}

	if e.Content != "" {
		return sanitizeTableString(p.text(e.Content), 85)
	}
	if e.Source != "" {
		return sanitizeTableString(p.text(e.Source), 85)
	}
	return "-"
}

func firstCommitLine(content string) string {
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Subject: [PATCH]") {
			return strings.TrimSpace(strings.TrimPrefix(l, "Subject: [PATCH]"))
		}
		if strings.HasPrefix(l, "Subject:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "Subject:"))
		}
	}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "From ") && !strings.HasPrefix(l, "Date:") && !strings.HasPrefix(l, "diff ") {
			return l
		}
	}
	return content
}

// renderGovulncheckComparison is audit-only: it aligns govulncheck
// reachability findings with the analyzer verdict and explains divergence.
func renderGovulncheckComparison(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	hasCallPaths := len(c.EvidenceGraph.CallPaths) > 0
	hasGovulncheckExec := false
	for _, tex := range c.EvidenceGraph.ToolExecutions {
		if tex.Tool == "govulncheck" {
			hasGovulncheckExec = true
			break
		}
	}
	if !hasCallPaths && !hasGovulncheckExec {
		return
	}

	var targets []string
	seen := map[string]bool{}
	for _, cp := range c.EvidenceGraph.CallPaths {
		if len(cp.Frames) > 0 {
			f := cp.Frames[0]
			var name string
			if f.Package != "" && f.Function != "" {
				name = f.Package + "." + f.Function
			} else if f.Function != "" {
				name = f.Function
			} else if f.Package != "" {
				name = f.Package
			}
			if name != "" && !seen[name] {
				seen[name] = true
				targets = append(targets, name)
			}
		}
	}

	absentPkgs, _, presentNotes := splitAdvisoryPackages(c)

	if isRU {
		b.WriteString("## Сопоставление с govulncheck\n\n")
		if hasCallPaths {
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Уязвимый код вызывается (Reachable)**\n")
			if len(targets) > 0 {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова от приложения к коду библиотеки (в частности: `%s`).\n", strings.Join(targets, "`, `"))
			} else {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова к коду библиотеки (%d).\n", len(c.EvidenceGraph.CallPaths))
			}
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
				b.WriteString("- 🛡️ **Вердикт анализатора:** **`NO_EXPLOIT_PATH_FOUND` (Уязвимый путь исполнения отсутствует)**\n")
				b.WriteString("- ⚖️ **Обоснование опровержения (почему срабатывание govulncheck является ложной тревогой):**\n")
				b.WriteString("  - **Смешение ролей функций в базе advisory:** `govulncheck` считает все перечисленные в advisory функции одинаково уязвимыми и не анализирует коммит исправления.\n")
				if len(presentNotes) > 0 {
					var syms []string
					for _, pn := range presentNotes {
						syms = append(syms, fmt.Sprintf("`%s.%s`", pn.Symbol.Package, pn.Symbol.Symbol))
					}
					fmt.Fprintf(b, "  - **Безопасность вызываемых функций:** Вызовы приходят в функции %s, которые выполняют лишь вспомогательную диспетчеризацию и не содержат дефектной операции.\n", strings.Join(syms, ", "))
				} else {
					b.WriteString("  - **Безопасность вызываемых функций:** Вызовы приходят в функции, которые признаны безопасными диспетчерами.\n")
				}
				if len(absentPkgs) > 0 {
					fmt.Fprintf(b, "  - **Физическое отсутствие дефектного локуса:** Реальный сайт сбоя находится в пакетах `%s`, которые **не скомпилированы в бинарный файл** (`go list -deps`).\n", strings.Join(absentPkgs, "`, `"))
				}
				b.WriteString("  - **Итог:** Вызовы, зафиксированные `govulncheck`, не приводят к исполнению дефекта (reachability false positive).\n\n")
			} else if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Вердикт анализатора:** **`EXPLOITABLE` (Уязвимость подтверждена)**\n")
				b.WriteString("- ⚖️ **Сопоставление:** Результаты согласуются — трасса вызовов подтверждает достижимость дефектного локуса.\n\n")
			} else if c.Verdict != nil {
				fmt.Fprintf(b, "- ⚠️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
				b.WriteString("- ⚖️ **Сопоставление:** `govulncheck` обнаружил вызовы к библиотеке; условия эксплуатации требуют дальнейшей проверки.\n\n")
			}
		} else {
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Трасса вызовов не обнаружена (Clean)**\n")
			b.WriteString("  - Сканер не нашёл статических путей вызова от кода приложения к функциям из advisory.\n")
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Вердикт анализатора:** **`EXPLOITABLE` (Уязвимость подтверждена)**\n")
				if hasMissingCall(c) {
					b.WriteString("- ⚖️ **Сопоставление (Расхождение с govulncheck):** `govulncheck` ищет вызовы функций из advisory, но дефект заключается в пропуске обязательной проверки (missing-call) на активном конвейере исполнения; условия эксплуатации подтверждены.\n\n")
				} else {
					b.WriteString("- ⚖️ **Сопоставление (Расхождение с govulncheck):** Сканер `govulncheck` не зафиксировал прямых вызовов функций из advisory, однако анализ подтвердил эксплуатируемость уязвимости.\n\n")
				}
			} else {
				if c.Verdict != nil {
					fmt.Fprintf(b, "- 🛡️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
				}
				b.WriteString("- ⚖️ **Сопоставление:** Результаты согласуются — вызовы уязвимых функций отсутствуют.\n\n")
			}
		}
	} else {
		b.WriteString("## Govulncheck comparison\n\n")
		if hasCallPaths {
			b.WriteString("- 🔍 **Govulncheck finding:** **Reachable (Vulnerable code is called)**\n")
			if len(targets) > 0 {
				fmt.Fprintf(b, "  - Scanner detected call paths from application code to library code (specifically: `%s`).\n", strings.Join(targets, "`, `"))
			} else {
				fmt.Fprintf(b, "  - Scanner detected %d call path(s) to library code.\n", len(c.EvidenceGraph.CallPaths))
			}
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
				b.WriteString("- 🛡️ **Analyzer verdict:** **`NO_EXPLOIT_PATH_FOUND` (No exploit path exists)**\n")
				b.WriteString("- ⚖️ **Divergence rationale (why govulncheck's warning is refuted):**\n")
				b.WriteString("  - **Undifferentiated advisory symbols:** `govulncheck` treats all symbols in the advisory record as equally vulnerable without analyzing patch semantics.\n")
				if len(presentNotes) > 0 {
					var syms []string
					for _, pn := range presentNotes {
						syms = append(syms, fmt.Sprintf("`%s.%s`", pn.Symbol.Package, pn.Symbol.Symbol))
					}
					fmt.Fprintf(b, "  - **Safety of called functions:** Calls reach functions %s, which perform only helper dispatching and contain no defective operation.\n", strings.Join(syms, ", "))
				} else {
					b.WriteString("  - **Safety of called functions:** Calls reach helper functions verified to be non-defective.\n")
				}
				if len(absentPkgs) > 0 {
					fmt.Fprintf(b, "  - **Physical absence of defect locus:** The actual crash site resides in packages `%s`, which are **not linked into the binary** (`go list -deps`).\n", strings.Join(absentPkgs, "`, `"))
				}
				b.WriteString("  - **Conclusion:** Call paths detected by `govulncheck` do not execute defective code (reachability false positive).\n\n")
			} else if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Analyzer verdict:** **`EXPLOITABLE` (Vulnerability confirmed)**\n")
				b.WriteString("- ⚖️ **Comparison:** Findings agree — call paths reach the active defect locus.\n\n")
			} else if c.Verdict != nil {
				fmt.Fprintf(b, "- ⚠️ **Analyzer verdict:** **`%s`**\n", c.Verdict.Verdict)
				b.WriteString("- ⚖️ **Comparison:** `govulncheck` detected library calls; exploit conditions require further evaluation.\n\n")
			}
		} else {
			b.WriteString("- 🔍 **Govulncheck finding:** **Clean (No call path found)**\n")
			b.WriteString("  - Scanner detected no static call paths from product code to advisory functions.\n")
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Analyzer verdict:** **`EXPLOITABLE` (Vulnerability confirmed)**\n")
				if hasMissingCall(c) {
					b.WriteString("- ⚖️ **Divergence rationale:** `govulncheck` checks for invocations of advisory functions, but the defect stems from omission of a security check (missing-call) along an active execution pipeline; exploit conditions are verified.\n\n")
				} else {
					b.WriteString("- ⚖️ **Divergence rationale:** `govulncheck` detected no direct call paths to advisory functions, but comprehensive analysis confirmed vulnerability exploitability.\n\n")
				}
			} else {
				if c.Verdict != nil {
					fmt.Fprintf(b, "- 🛡️ **Analyzer verdict:** **`%s`**\n", c.Verdict.Verdict)
				}
				b.WriteString("- ⚖️ **Comparison:** Findings agree — no calls to vulnerable functions detected.\n\n")
			}
		}
	}
}

func localizeClaimExplanation(expl string, isRU bool) string {
	if !isRU || expl == "" {
		return expl
	}
	switch expl {
	case "govulncheck produced call path(s) to the affected symbol(s)":
		return "Трасса вызовов govulncheck достигает уязвимых символов библиотеки"
	case "no call path from application to affected symbol(s)":
		return "Пути вызова от приложения к уязвимым символам отсутствуют"
	case "all mandatory exploit conditions are satisfied":
		return "Все обязательные условия эксплуатации выполнены"
	case "condition unresolved":
		return "Условие не определено (недостаточно данных)"
	case "outbound destination endpoints are statically configured or loaded from trusted configuration: remote backends are operator-managed",
		"outbound destination endpoints are statically configured or loaded from trusted configuration (config-origin)":
		return "Адреса исходящих подключений статически заданы в коде или конфигурации: удалённые сервисы доверены"
	case "vulnerability is server-side (requires incoming requests), but product has no inbound server listener for the vulnerable module (outbound clients only)":
		return "Уязвимость на стороне сервера (требует входящих запросов), но в продукте нет слушателей для уязвимого модуля (только клиенты)"
	case "vulnerability is client-side (requires outbound response parsing), but product operates purely as a server (inbound listeners present, no outbound client call sites into vulnerable module)":
		return "Уязвимость на стороне клиента (требует разбора ответов), но продукт работает исключительно как сервер (только слушатели)"
	case "deployment infrastructure declared trusted peer communication (--trusted-peer): network traffic and remote peers/brokers are authenticated and trusted":
		return "Инфраструктура объявлена доверенной: сетевой трафик и узлы кластера аутентифицированы и доверены"
	case "FALSE is decided by trusted cluster infrastructure / perimeter":
		return "Условие нейтрализовано доверенной сетевой инфраструктурой кластера"
	}

	res := expl
	if strings.HasPrefix(res, "govulncheck found no call path to any of ") {
		res = strings.Replace(res, "govulncheck found no call path to any of ", "govulncheck не обнаружил путей вызова к ", 1)
		res = strings.Replace(res, " affected symbol(s)", " уязвимым символам", 1)
	} else if strings.HasPrefix(res, "inbound surface wired behind auth check(s): ") {
		res = "Входящий интерфейс защищён проверкой аутентификации: " + strings.TrimPrefix(res, "inbound surface wired behind auth check(s): ")
	} else if strings.HasPrefix(res, "all call path(s) to affected symbol(s) are dead code under disabled feature gates") {
		res = "Все пути вызова к уязвимым символам находятся в мёртвом коде за отключёнными флагами"
	} else if strings.HasPrefix(res, "all resolved inbound network binds are loopback/cluster-internal; public network exposure falsified: ") {
		res = "Все входящие интерфейсы привязаны к локальным или кластерным адресам: " + strings.TrimPrefix(res, "all resolved inbound network binds are loopback/cluster-internal; public network exposure falsified: ")
	} else if strings.HasPrefix(res, "network exposure resolved: ") {
		res = "Сетевая доступность подтверждена: " + strings.TrimPrefix(res, "network exposure resolved: ")
	} else if strings.Contains(res, "call site(s) receive externally controlled input") {
		if strings.HasPrefix(res, "1 ") {
			res = strings.Replace(res, "1 call site(s) receive externally controlled input", "1 точка вызова принимает входные данные извне", 1)
		} else {
			res = strings.Replace(res, "call site(s) receive externally controlled input", "точек вызова принимают входные данные извне", 1)
		}
	} else if strings.Contains(res, "call site(s) receive non-external input") {
		if strings.HasPrefix(res, "1 ") {
			res = strings.Replace(res, "1 call site(s) receive non-external input", "1 точка вызова получает не-внешние данные", 1)
		} else {
			res = strings.Replace(res, "call site(s) receive non-external input", "точек вызова получают не-внешние данные", 1)
		}
	} else if strings.Contains(res, "never assigned in product code — Go zero value false is not") {
		res = "Параметр никогда не присваивается в коде (значение по умолчанию false)"
	} else if strings.Contains(res, "assigned only safe value(s)") {
		res = "Параметру присваиваются только безопасные значения"
	} else if strings.Contains(res, "set to insecure value") {
		res = "Параметр установлен в небезопасное значение"
	}

	return sanitizeTableString(res, 120)
}

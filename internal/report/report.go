// Package report renders the AnalysisCase into the persisted JSON artifact,
// a short human-readable/tracker-ready markdown summary (Markdown) and a
// full technical audit document (AuditMarkdown).
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/risk"
)

// Write stores report.json, openvex.json, cyclonedx.json, the human reports
// (report.md / report.en.md) and the technical audit reports
// (report.audit.md / report.audit.en.md) inside dir.
func Write(dir string, c *domain.AnalysisCase) error {
	populateUpgradeCompatibility(c)
	ensureTriageAssessment(c)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), jb, 0o644); err != nil {
		return err
	}
	vb, err := OpenVEX(c)
	if err != nil {
		return fmt.Errorf("openvex: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openvex.json"), vb, 0o644); err != nil {
		return err
	}
	cb, err := CycloneDX(c)
	if err != nil {
		return fmt.Errorf("cyclonedx: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cyclonedx.json"), cb, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(c, "ru")), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.en.md"), []byte(Markdown(c, "en")), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.audit.md"), []byte(AuditMarkdown(c, "ru")), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.audit.en.md"), []byte(AuditMarkdown(c, "en")), 0o644)
}

// ensureTriageAssessment normalizes the persisted ContextualRisk before any
// report is rendered or serialized: legacy cases may carry a risk record
// computed before disposition/provenance fields existed, or a verdict that
// was rewritten after triage. The assessment is re-run only in those cases.
// It never invents a verdict: when c.Verdict is nil the record stays absent
// and the renderers state that the verdict was not produced.
func ensureTriageAssessment(c *domain.AnalysisCase) {
	if c == nil || c.Verdict == nil {
		return
	}
	final := string(c.Verdict.Verdict)
	// SeveritySource/ScoreSource are legitimately empty for scanner-input
	// vulnerabilities, so they are not part of the freshness contract — a
	// persisted assessment with a disposition and baseline priority that
	// matches the final verdict is reused as-is.
	if r := c.ContextualRisk; r != nil &&
		r.TriageDisposition != "" &&
		r.BasePriority != "" &&
		r.Factors.Verdict == final {
		return
	}
	res := risk.Assess(c.Vulnerability, c, *c.Verdict)
	c.ContextualRisk = &res
}

func isRussian(lang ...string) bool {
	if len(lang) > 0 && strings.EqualFold(strings.TrimSpace(lang[0]), "en") {
		return false
	}
	return true
}

var verdictReasonRU = map[string]string{
	"mandatory exploit condition is proven false":                               "Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)",
	"all mandatory exploit conditions are satisfied":                            "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)",
	"all mandatory conditions met":                                              "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)",
	"vulnerable module is not part of the product dependency graph":             "Уязвимый модуль не входит в граф зависимостей продукта",
	"resolved dependency version is outside affected range":                     "Разрешённая версия зависимости находится вне уязвимого диапазона",
	"resolved version outside affected range":                                   "Разрешённая версия библиотеки находится вне уязвимого диапазона",
	"affected package is not imported by the product build":                     "Уязвимый пакет не импортируется в сборке продукта",
	"package is not linked in build":                                            "Уязвимый пакет не слинкован в сборке продукта",
	"affected packages are constrained to other platforms/build configurations": "Уязвимые пакеты ограничены другими платформами или конфигурациями сборки",
	"no exploit conditions met":                                                 "Ни одно условие эксплуатации не выполнено",
	"locus packages absent from build graph":                                    "Уязвимый код физически не включён в сборку",
	"one or more mandatory exploit conditions remain unresolved":                "Одно или несколько обязательных условий эксплуатации не подтверждены",
}

func localizeVerdictReason(reason string, isRU bool) string {
	if !isRU {
		return reason
	}
	if s, ok := verdictReasonRU[reason]; ok {
		return s
	}

	if strings.HasPrefix(reason, "one or more mandatory exploit conditions remain unresolved:") {
		unresolved := strings.TrimSpace(strings.TrimPrefix(reason, "one or more mandatory exploit conditions remain unresolved:"))
		return "Одно или несколько обязательных условий эксплуатации не подтверждены: " + unresolved
	}
	if strings.HasPrefix(reason, "resolved version ") && strings.Contains(reason, " is outside the affected range") {
		ver := strings.TrimPrefix(reason, "resolved version ")
		ver = strings.TrimSuffix(ver, " is outside the affected range")
		return fmt.Sprintf("Разрешённая версия %s находится вне уязвимого диапазона", ver)
	}
	if strings.HasPrefix(reason, "none of the affected module(s) ") && strings.Contains(reason, " resolve to a product dependency") {
		parts := strings.Split(strings.TrimPrefix(reason, "none of the affected module(s) "), " resolve to a product dependency")
		mods := parts[0]
		return fmt.Sprintf("Ни один из уязвимых модулей %s не входит в зависимости продукта (go list -m all)", mods)
	}
	if strings.HasPrefix(reason, "affected package(s) ") && strings.Contains(reason, " are absent from the product's transitive import closure") {
		parts := strings.Split(strings.TrimPrefix(reason, "affected package(s) "), " are absent from the product's transitive import closure")
		pkgs := parts[0]
		return fmt.Sprintf("Уязвимый пакет(ы) %s отсутствует в транзитивном графе импортов сборки (go list -deps -test ./...) — код не скомпилирован в продукт", pkgs)
	}
	if strings.HasPrefix(reason, "all modeled mandatory conditions are satisfied, but ") {
		return "Все смоделированные обязательные условия выполнены, но часть дефектных точек сбоя (sinks) не разрешена или отсутствует в сборке: модель усечена и не может обосновать положительный вердикт"
	}
	if strings.HasPrefix(reason, "cluster-perimeter verdict rests on a declared trust boundary, but ") {
		return "Вердикт внутрикластерного периметра опирается на объявленную границу доверия, но часть заявленных в advisory функций не разрешена: утверждение оператора не может закрыть несмоделированный путь атаки"
	}

	return reason
}

var conditionDescRU = map[string]string{
	"C-REACH":      "Достижимость символов: хотя бы одна из уязвимых функций вызывается в коде продукта",
	"C-PEER-INPUT": "Контроль ввода: параметры уязвимой функции контролируются удалённым клиентом",
	"C-CONSTRAINT": "Нарушение ограничений: удалённый клиент может передать входные данные, вызывающие сбой",
	"C-LOCUS":      "Выполнение уязвимого кода: пакеты дефектного кода входят в граф сборки приложения",
	"C-EXPOSURE":   "Сетевая доступность: наличие открытых сетевых портов или исходящих подключений",
	"C-TLS-VERIFY": "Проверка TLS: отключение проверки сертификатов позволяет передавать трафик без доверенного канала",
}

func localizeConditionDesc(id string, defaultDesc string, isRU bool) string {
	if !isRU {
		return defaultDesc
	}
	if s, ok := conditionDescRU[id]; ok {
		return s
	}
	return defaultDesc
}

func rootCauseMechanism(mech string, isRU bool) string {
	if isRU {
		if mech == "advisory-listed affected symbol" {
			return "заявлена как уязвимая в базе (advisory)"
		}
		return strings.ReplaceAll(mech, "advisory-listed affected symbol", "заявлена как уязвимая в базе (advisory)")
	}
	return mech
}

// internalIDRe matches internal artifact identifiers (C-*, EV-*, TX-*,
// H-<n>, REV-<n>) that must never leak into the human report — they stay in
// the technical audit.
var internalIDRe = regexp.MustCompile(`\b(?:C|EV|TX|REV)-[A-Z0-9]|\bH-\d`)

// Markdown renders the human report: nine fixed sections, verdict first,
// no internal ids or audit structures. Russian is the default language.
func Markdown(c *domain.AnalysisCase, lang ...string) string {
	ensureTriageAssessment(c)
	populateUpgradeCompatibility(c)
	isRU := isRussian(lang...)
	p := newReportPaths(c)
	var b strings.Builder

	fmt.Fprintf(&b, "# %s — %s\n\n", c.Vulnerability.ID, p.text(essenceTitle(c, isRU)))
	writeCaseMetadata(&b, c, isRU)

	renderExecutiveVerdict(&b, c, p, isRU)
	renderVulnerabilityEssence(&b, c, p, isRU)
	renderProductExploitPath(&b, c, p, isRU)
	renderConfirmedFacts(&b, c, p, isRU)
	renderUnknowns(&b, c, p, isRU)
	renderTriageDecision(&b, c, p, isRU)
	renderRemediation(&b, c, p, isRU)
	renderAIUsage(&b, c, p, isRU)
	renderAuditLink(&b, c, isRU)

	return b.String()
}

func writeCaseMetadata(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	type field struct {
		ru, en, val string
	}
	fields := []field{
		{"Кейс", "Case", string(c.ID)},
		{"Тикет", "Ticket", c.TicketID},
		{"Компонент", "Component", c.TicketComponent},
		{"Релиз", "Release", c.TicketRelease},
		{"Репозиторий", "Repository", reportRepositoryName(c.Product.Repository)},
		{"Коммит", "Commit", c.Product.Commit},
	}
	for _, f := range fields {
		if f.val == "" {
			continue
		}
		label := f.en
		if isRU {
			label = f.ru
		}
		fmt.Fprintf(b, "- %s: `%s`\n", label, f.val)
	}
	b.WriteString("\n")
}

// essenceTitle builds the short human title for the H1: first short Summary
// line, else first Description line, else the confirmed mechanism, else an
// explicit "mechanism not established" phrase. External prose is used as a
// source quote only — never auto-translated or asserted as product fact.
func essenceTitle(c *domain.AnalysisCase, isRU bool) string {
	short := func(s string) string {
		s = firstTextLine(s)
		if s == "" {
			return ""
		}
		if idx := strings.Index(s, ". "); idx > 0 && idx < 120 {
			s = s[:idx]
		}
		if r := []rune(s); len(r) > 120 {
			s = string(r[:119]) + "…"
		}
		return strings.TrimRight(s, ". ")
	}
	if s := localizedAdvisory(c, "summary", isRU); s != "" {
		if t := short(s); t != "" {
			return t
		}
	}
	if s := short(c.Vulnerability.Summary); s != "" {
		return s
	}
	if d := localizedAdvisory(c, "description", isRU); d != "" {
		if s := short(d); s != "" {
			return s
		}
	} else if s := short(c.Vulnerability.Description); s != "" {
		return s
	}
	if c.RootCause != nil && c.RootCause.Status == domain.RootCauseResolved {
		for _, rc := range c.RootCause.RootCauses {
			if rc.Absent || rc.Mechanism == "" || strings.Contains(strings.ToLower(rc.Mechanism), "advisory") {
				continue
			}
			return rootCauseMechanism(rc.Mechanism, isRU)
		}
	}
	if isRU {
		return "механизм уязвимости не установлен"
	}
	return "vulnerability mechanism not established"
}

func firstTextLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func firstParagraph(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "\n\n"); idx > 0 {
		s = s[:idx]
	}
	if len(s) > 400 {
		if idx := strings.Index(s[200:], ". "); idx > 0 {
			s = s[:200+idx+1]
		}
	}
	return strings.TrimSpace(s)
}

func verdictTitle(v domain.Verdict, isRU bool) string {
	if v == "" {
		if isRU {
			return "вердикт не вынесен"
		}
		return "verdict not available"
	}
	return string(v)
}

// advisorySeveritySupplied reports whether the advisory/scanner record
// itself carried a severity value — an analyzer-synthesized or unlabeled
// baseline (empty source, or the SourceAnalyzerDefault marker the risk
// layer stamps on defaults) is not an advisory assessment.
func advisorySeveritySupplied(c *domain.AnalysisCase) bool {
	if c.Vulnerability.BaseSeverity == "" {
		return false
	}
	src := c.Vulnerability.SeveritySource
	return src != "" && src != domain.SourceAnalyzerDefault
}

func advisoryScoreSupplied(c *domain.AnalysisCase) bool {
	if c.Vulnerability.BaseScore <= 0 {
		return false
	}
	src := c.Vulnerability.ScoreSource
	return src != "" && src != domain.SourceAnalyzerDefault
}

// baseSeverityText renders the baseline severity for the human report.
// When the advisory supplied no assessment the value is an honest
// "not supplied" — a synthesized analyzer baseline is never presented as
// an advisory rating.
func baseSeverityText(c *domain.AnalysisCase, isRU bool) string {
	sev, score := "", 0.0
	if advisorySeveritySupplied(c) {
		sev = strings.ToUpper(strings.TrimSpace(c.Vulnerability.BaseSeverity))
	}
	if advisoryScoreSupplied(c) {
		score = c.Vulnerability.BaseScore
	}
	if sev == "" {
		if isRU {
			sev = "не указана"
		} else {
			sev = "not supplied"
		}
	}
	if score > 0 {
		if isRU {
			return fmt.Sprintf("%s, исходный балл %.1f", sev, score)
		}
		return fmt.Sprintf("%s, base score %.1f", sev, score)
	}
	return sev
}

func severitySource(c *domain.AnalysisCase) string {
	if !advisorySeveritySupplied(c) {
		return ""
	}
	if c.ContextualRisk != nil && c.ContextualRisk.SeveritySource != "" &&
		c.ContextualRisk.SeveritySource != domain.SourceAnalyzerDefault {
		return c.ContextualRisk.SeveritySource
	}
	if c.Vulnerability.SeveritySource != "" {
		return c.Vulnerability.SeveritySource
	}
	if s := c.Vulnerability.Provenance["severity_source"]; s != "" {
		return s
	}
	return "Scanner input"
}

func scoreSource(c *domain.AnalysisCase) string {
	if !advisoryScoreSupplied(c) {
		return ""
	}
	if c.ContextualRisk != nil && c.ContextualRisk.ScoreSource != "" &&
		c.ContextualRisk.ScoreSource != domain.SourceAnalyzerDefault {
		return c.ContextualRisk.ScoreSource
	}
	if c.Vulnerability.ScoreSource != "" {
		return c.Vulnerability.ScoreSource
	}
	if s := c.Vulnerability.Provenance["score_source"]; s != "" {
		return s
	}
	return "Scanner input"
}

// sourceText renders the assessment provenance line. When neither value
// came from the advisory the displayed source is the analyzer's own
// default — never an advisory label like "OSV".
func sourceText(c *domain.AnalysisCase, isRU bool) string {
	if !advisorySeveritySupplied(c) && !advisoryScoreSupplied(c) {
		if isRU {
			return "умолчание анализатора (advisory оценку не сообщил)"
		}
		return "analyzer default (advisory supplied no assessment)"
	}
	sev, score := severitySource(c), scoreSource(c)
	if sev == "" {
		sev = score
	}
	if score == "" {
		score = sev
	}
	if sev == score {
		return sev
	}
	return sev + " / " + score
}

func priorityText(p domain.TriagePriority, isRU bool) string {
	if p == "" {
		return "—"
	}
	return formatTriagePriority(p, isRU)
}

// dispositionSuffix renders the short human qualifier appended to the
// executive priority line, e.g. " — без изменения" / " — unchanged".
func dispositionSuffix(c *domain.AnalysisCase, isRU bool) string {
	if c.ContextualRisk == nil {
		return ""
	}
	switch c.ContextualRisk.TriageDisposition {
	case domain.TriageUnchanged:
		if isRU {
			return " — без изменения"
		}
		return " — unchanged"
	case domain.TriageLowered:
		if isRU {
			return " — приоритет снижен"
		}
		return " — priority lowered"
	case domain.TriageDismissed:
		if isRU {
			return " — finding можно закрыть"
		}
		return " — the finding can be closed"
	case domain.TriageInconclusive:
		if isRU {
			return " — требуется дополнительная проверка"
		}
		return " — additional verification required"
	}
	return ""
}

func effectiveBasePriority(c *domain.AnalysisCase) domain.TriagePriority {
	if c.ContextualRisk != nil && c.ContextualRisk.BasePriority != "" {
		return c.ContextualRisk.BasePriority
	}
	sev, score := "", 0.0
	if c.ContextualRisk != nil {
		sev = c.ContextualRisk.BaseSeverity
		score = c.ContextualRisk.BaseScore
	}
	if sev == "" {
		sev = c.Vulnerability.BaseSeverity
	}
	if score <= 0 {
		score = c.Vulnerability.BaseScore
	}
	return risk.NominalPriority(sev, score)
}

func claimByCondition(c *domain.AnalysisCase) map[domain.ConditionID]domain.Claim {
	m := make(map[domain.ConditionID]domain.Claim, len(c.Claims))
	for _, cl := range c.Claims {
		m[cl.ConditionID] = cl
	}
	return m
}

// dedupeStrings removes duplicate entries while preserving first-seen order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// externalOrigin reports whether a data-flow origin is attacker-controlled
// external input — the only origin that may ground a human "input reaches
// sink" statement. Constant/configuration/generated/internal/database
// origins are trusted or derived facts and unknown is not evidence.
func externalOrigin(o domain.DataOrigin) bool {
	switch o {
	case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated:
		return true
	default:
		return false
	}
}

func allConditions(c *domain.AnalysisCase) []domain.Condition {
	if c.Exploit == nil {
		return nil
	}
	return append(append([]domain.Condition{}, c.Exploit.MandatoryConditions...), c.Exploit.SupportingFactors...)
}

func conditionByID(c *domain.AnalysisCase, id domain.ConditionID) *domain.Condition {
	conds := allConditions(c)
	for i := range conds {
		if conds[i].ID == id {
			return &conds[i]
		}
	}
	return nil
}

var conditionKindRU = map[domain.ConditionKind]string{
	domain.ConditionSymbolReachable: "достижимость уязвимого символа",
	domain.ConditionAttackerControl: "контроль входных данных атакующим",
	domain.ConditionInputConstraint: "нарушение ограничений входных данных",
	domain.ConditionValidation:      "условие валидации",
	domain.ConditionConfiguration:   "условие конфигурации",
	domain.ConditionBuild:           "условие сборки",
	domain.ConditionPlatform:        "платформенное условие",
	domain.ConditionAuthn:           "условие аутентификации",
	domain.ConditionRuntime:         "условие среды выполнения",
	domain.ConditionMissingCall:     "пропущенная обязательная проверка",
	domain.ConditionCustom:          "дополнительное условие",
}

var conditionKindEN = map[domain.ConditionKind]string{
	domain.ConditionSymbolReachable: "vulnerable symbol reachability",
	domain.ConditionAttackerControl: "attacker control of input data",
	domain.ConditionInputConstraint: "input constraint violation",
	domain.ConditionValidation:      "validation condition",
	domain.ConditionConfiguration:   "configuration condition",
	domain.ConditionBuild:           "build condition",
	domain.ConditionPlatform:        "platform condition",
	domain.ConditionAuthn:           "authentication condition",
	domain.ConditionRuntime:         "runtime condition",
	domain.ConditionMissingCall:     "missing mandatory check",
	domain.ConditionCustom:          "additional condition",
}

// conditionHumanDesc renders a condition in human form — localized
// description or kind — never the internal condition id.
func conditionHumanDesc(cond domain.Condition, isRU bool) string {
	desc := localizeConditionDesc(string(cond.ID), cond.Description, isRU)
	if desc != "" && !internalIDRe.MatchString(desc) {
		return desc
	}
	if isRU {
		if s, ok := conditionKindRU[cond.Kind]; ok {
			return s
		}
		return "условие эксплуатации"
	}
	if s, ok := conditionKindEN[cond.Kind]; ok {
		return s
	}
	return "exploit condition"
}

// renderExecutiveVerdict renders the first section: final verdict, one short
// verdict-dependent phrase, base severity with provenance, effective
// priority and a short triage reason. Internal statuses, contextual score
// and SLA stay in the audit report.
func renderExecutiveVerdict(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	v := domain.Verdict("")
	if c.Verdict != nil {
		v = c.Verdict.Verdict
	}
	if isRU {
		fmt.Fprintf(b, "## Результат: %s\n\n", verdictTitle(v, true))
	} else {
		fmt.Fprintf(b, "## Result: %s\n\n", verdictTitle(v, false))
	}

	switch v {
	case domain.VerdictExploitable:
		if isRU {
			b.WriteString("Уязвимость применима к продукту и подтверждена в пределах проведённого анализа.\n\n")
		} else {
			b.WriteString("The vulnerability applies to the product and was confirmed within the performed analysis.\n\n")
		}
	case domain.VerdictNotAffected:
		cause := notAffectedCause(c, isRU)
		if isRU {
			fmt.Fprintf(b, "Уязвимость не применима к данному продукту: %s.\n\n", cause)
		} else {
			fmt.Fprintf(b, "The vulnerability does not apply to this product: %s.\n\n", cause)
		}
	case domain.VerdictNoExploitPathFound:
		if isRU {
			fmt.Fprintf(b, "Уязвимый путь исполнения отсутствует: %s.\n\n", falsifiedConditionDesc(c, true))
		} else {
			fmt.Fprintf(b, "No exploit path exists: %s.\n\n", falsifiedConditionDesc(c, false))
		}
	case domain.VerdictInconclusive:
		if isRU {
			b.WriteString("Однозначный вывод сделать не удалось: часть обязательных условий не подтверждена и не опровергнута; исходный приоритет сохранён.\n\n")
		} else {
			b.WriteString("The analysis could not reach a definitive conclusion: some mandatory conditions are neither confirmed nor falsified; the baseline priority is retained.\n\n")
		}
	default:
		if isRU {
			b.WriteString("Анализ уязвимости не завершён — вердикт не вынесен.\n\n")
		} else {
			b.WriteString("The vulnerability analysis did not complete — verdict not available.\n\n")
		}
	}

	if isRU {
		fmt.Fprintf(b, "**Исходная критичность:** %s\n", baseSeverityText(c, true))
		fmt.Fprintf(b, "**Источник оценки:** %s\n", sourceText(c, true))
	} else {
		fmt.Fprintf(b, "**Baseline severity:** %s\n", baseSeverityText(c, false))
		fmt.Fprintf(b, "**Assessment source:** %s\n", sourceText(c, false))
	}
	if c.ContextualRisk != nil {
		suffix := dispositionSuffix(c, isRU)
		if isRU {
			fmt.Fprintf(b, "**Приоритет:** %s%s\n\n", priorityText(c.ContextualRisk.Priority, true), suffix)
		} else {
			fmt.Fprintf(b, "**Priority:** %s%s\n\n", priorityText(c.ContextualRisk.Priority, false), suffix)
		}
		switch c.ContextualRisk.TriageDisposition {
		case domain.TriageUnchanged:
			if isRU {
				b.WriteString("Контекстный анализ не выявил оснований для снижения исходной оценки.\n\n")
			} else {
				b.WriteString("The contextual analysis found no grounds to lower the baseline assessment.\n\n")
			}
		case domain.TriageLowered:
			if isRU {
				b.WriteString("Подтверждённый контекст развёртывания позволяет снизить исходный приоритет; подробности — в разделе «Оценка и приоритет».\n\n")
			} else {
				b.WriteString("The confirmed deployment context allows lowering the baseline priority; see the \u201cAssessment and priority\u201d section.\n\n")
			}
		case domain.TriageDismissed:
			if isRU {
				b.WriteString("Приоритет устранения снят: уязвимость неприменима к проверенному снимку.\n\n")
			} else {
				b.WriteString("The remediation priority is dismissed: the vulnerability does not apply to the verified snapshot.\n\n")
			}
		case domain.TriageInconclusive:
			if isRU {
				b.WriteString("Исходный приоритет сохранён — требуется дополнительная проверка.\n\n")
			} else {
				b.WriteString("The baseline priority is retained — additional verification is required.\n\n")
			}
		}
	}
	if c.ContextualRisk == nil {
		b.WriteString("\n")
	}

	if c.Verdict != nil && c.Verdict.Reason != "" && !internalIDRe.MatchString(c.Verdict.Reason) {
		if isRU {
			fmt.Fprintf(b, "> %s\n\n", localizeVerdictReason(p.text(c.Verdict.Reason), true))
		} else {
			fmt.Fprintf(b, "> %s\n\n", p.text(c.Verdict.Reason))
		}
	}
}

// notAffectedCause names the real verified cause of a NOT_AFFECTED verdict:
// version outside the range, module absent, package not linked, or build
// constraint — never a generic "no risk" phrase.
func notAffectedCause(c *domain.AnalysisCase, isRU bool) string {
	mod, ver := moduleAndVersion(c)
	if c.Affected != nil {
		a := c.Affected
		switch {
		case a.ModulePresent == domain.ClaimFalse:
			if isRU {
				return fmt.Sprintf("модуль `%s` не входит в граф зависимостей продукта (`go list -m all`)", mod)
			}
			return fmt.Sprintf("module `%s` is not part of the product dependency graph (`go list -m all`)", mod)
		case a.VersionAffected == domain.ClaimFalse:
			if isRU {
				return fmt.Sprintf("используемая версия `%s %s` находится вне уязвимого диапазона версий", mod, ver)
			}
			return fmt.Sprintf("the version in use `%s %s` is outside the affected version range", mod, ver)
		case a.PackagePresent == domain.ClaimFalse:
			if isRU {
				return "уязвимые пакеты не входят в транзитивное замыкание сборки (`go list -deps`) — код не скомпилирован в продукт"
			}
			return "affected packages are absent from the transitive import closure (`go list -deps`) — the code is not linked into the product"
		case a.BuildRelevant == domain.ClaimFalse:
			if isRU {
				return "код уязвимого пакета не компилируется для целевой платформы или конфигурации сборки"
			}
			return "the affected package does not compile for the target platform or build configuration"
		}
	}
	if c.Verdict != nil && c.Verdict.Reason != "" && !internalIDRe.MatchString(c.Verdict.Reason) {
		return localizeVerdictReason(c.Verdict.Reason, isRU)
	}
	if isRU {
		return "применимость опровергнута проверками сборки"
	}
	return "applicability was falsified by build checks"
}

// falsifiedConditionDesc names the verified falsified mandatory condition in
// human form for a NO_EXPLOIT_PATH_FOUND verdict.
func falsifiedConditionDesc(c *domain.AnalysisCase, isRU bool) string {
	claims := claimByCondition(c)
	if c.Verdict != nil {
		for _, id := range c.Verdict.ConditionIDs {
			cl, ok := claims[id]
			if !ok || cl.Result != domain.ClaimFalse {
				continue
			}
			if cond := conditionByID(c, id); cond != nil {
				return conditionHumanDesc(*cond, isRU)
			}
		}
	}
	for _, cond := range allConditions(c) {
		if !cond.Mandatory {
			continue
		}
		if cl, ok := claims[cond.ID]; ok && cl.Result == domain.ClaimFalse {
			return conditionHumanDesc(cond, isRU)
		}
	}
	if isRU {
		return "обязательное условие эксплуатации опровергнуто"
	}
	return "a mandatory exploit condition was proven false"
}

// localizedText returns the Russian rendering of an externally sourced
// string when a translation is available for the RU report; otherwise the
// original text is returned unchanged. Translation never replaces the
// authoritative source — it is presentation only.
func localizedText(c *domain.AnalysisCase, original string, isRU bool) string {
	if !isRU || original == "" || c.Localization == nil {
		return original
	}
	if t := c.Localization.TextRU[original]; t != "" {
		return t
	}
	return original
}

// localizedAdvisory returns the Russian rendering of the advisory
// summary/description when translation is available, else the original.
func localizedAdvisory(c *domain.AnalysisCase, kind string, isRU bool) string {
	if !isRU || c.Localization == nil {
		return ""
	}
	switch kind {
	case "summary":
		return c.Localization.SummaryRU
	case "description":
		return c.Localization.DescriptionRU
	}
	return ""
}

// pickMechanism selects the best available defect-mechanism description and
// records its provenance: "rootcause" (deterministically resolved),
// "advisory" (external advisory text), "ai" (unconfirmed LLM proposal) or
// "none".
func pickMechanism(c *domain.AnalysisCase, isRU bool) (text, source string) {
	if c.RootCause != nil && c.RootCause.Status == domain.RootCauseResolved {
		var parts []string
		for _, rc := range c.RootCause.RootCauses {
			if rc.Absent || rc.Mechanism == "" || strings.Contains(strings.ToLower(rc.Mechanism), "advisory") {
				continue
			}
			mech := rootCauseMechanism(rc.Mechanism, isRU)
			if t := localizedText(c, rc.Mechanism, isRU); t != rc.Mechanism {
				mech = t
			}
			parts = append(parts, fmt.Sprintf("%s (`%s.%s`)", mech, rc.Package, rc.Symbol))
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; "), "rootcause"
		}
	}
	if d := localizedAdvisory(c, "description", isRU); d != "" {
		return firstParagraph(d), "advisory"
	}
	if d := firstParagraph(c.Vulnerability.Description); d != "" {
		return d, "advisory"
	}
	if s := localizedAdvisory(c, "summary", isRU); s != "" {
		return firstTextLine(s), "advisory"
	}
	if s := firstTextLine(c.Vulnerability.Summary); s != "" {
		return s, "advisory"
	}
	if c.CVEAnalysis != nil && len(c.CVEAnalysis.Mechanisms) > 0 && c.CVEAnalysis.Mechanisms[0].Summary != "" {
		return localizedText(c, c.CVEAnalysis.Mechanisms[0].Summary, isRU), "ai"
	}
	if c.RootCause != nil {
		for _, rc := range c.RootCause.RootCauses {
			if rc.Absent {
				continue
			}
			if isRU {
				return fmt.Sprintf("дефект локализован в `%s.%s` — детали механизма не зафиксированы", rc.Package, rc.Symbol), "rootcause"
			}
			return fmt.Sprintf("defect localized at `%s.%s` — mechanism details not recorded", rc.Package, rc.Symbol), "rootcause"
		}
	}
	if isRU {
		return "Механизм уязвимости не установлен.", "none"
	}
	return "Vulnerability mechanism not established.", "none"
}

// defectDescription returns the best available human description of the
// defect mechanism; unconfirmed sources (advisory text, LLM proposals) are
// marked with their provenance, and a missing mechanism is explicit.
func defectDescription(c *domain.AnalysisCase, p reportPaths, isRU bool) string {
	text, src := pickMechanism(c, isRU)
	text = p.text(text)
	switch src {
	case "advisory":
		if isRU {
			return "По данным advisory: " + text
		}
		return "Per advisory: " + text
	case "ai":
		if isRU {
			return "Предложение AI-анализа (не подтверждено детерминистически): " + text
		}
		return "Proposed by AI analysis (not deterministically confirmed): " + text
	}
	return text
}

// sinkSymbols returns resolved defect sinks (SINK role first, then other
// resolved non-absent root causes). An ENTRYPOINT is never promoted to the
// defect sink — entry points are origins, not the vulnerable operation.
func sinkSymbols(c *domain.AnalysisCase) []domain.SymbolRef {
	if c.RootCause == nil || c.RootCause.Status != domain.RootCauseResolved {
		return nil
	}
	var sinks, others []domain.SymbolRef
	for _, rc := range c.RootCause.RootCauses {
		if rc.Absent {
			continue
		}
		ref := domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol}
		if rc.Role == domain.RootCauseSink {
			sinks = append(sinks, ref)
		} else if rc.Role != domain.RootCauseEntrypoint {
			others = append(others, ref)
		}
	}
	if len(sinks) > 0 {
		return sinks
	}
	return others
}

// renderVulnerabilityEssence explains the defect mechanism, the vulnerable
// operation and the recorded impact. It never invents panic/DoS/RCE/leak
// statements — impact is only what the case recorded.
func renderVulnerabilityEssence(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if isRU {
		b.WriteString("## В чём уязвимость\n\n")
	} else {
		b.WriteString("## Vulnerability overview\n\n")
	}

	fmt.Fprintf(b, "%s\n\n", defectDescription(c, p, isRU))

	if syms := sinkSymbols(c); len(syms) > 0 {
		var names []string
		for _, s := range syms {
			names = append(names, fmt.Sprintf("`%s.%s`", s.Package, s.Symbol))
		}
		if isRU {
			fmt.Fprintf(b, "- **Уязвимая операция:** %s\n", strings.Join(names, ", "))
		} else {
			fmt.Fprintf(b, "- **Vulnerable operation:** %s\n", strings.Join(names, ", "))
		}
	}

	impact := ""
	if c.Exploit != nil {
		impact = p.text(localizedText(c, c.Exploit.Impact, isRU))
	}
	if impact != "" {
		if isRU {
			fmt.Fprintf(b, "- **Зафиксированное последствие:** %s\n", impact)
		} else {
			fmt.Fprintf(b, "- **Recorded impact:** %s\n", impact)
		}
	}

	// CWE codes are advisory metadata and stay as recorded; the inferred
	// exploit class is an internal enum — it renders as a localized human
	// label here, while the raw value remains in audit/JSON.
	if class := strings.Join(c.Vulnerability.CWE, ", "); class != "" {
		if isRU {
			fmt.Fprintf(b, "- **Класс дефекта:** `%s`\n", class)
		} else {
			fmt.Fprintf(b, "- **Defect class:** `%s`\n", class)
		}
	} else if c.Exploit != nil && c.Exploit.Class != "" {
		if isRU {
			fmt.Fprintf(b, "- **Класс дефекта:** %s\n", exploitClassLabel(c.Exploit.Class, true))
		} else {
			fmt.Fprintf(b, "- **Defect class:** %s\n", exploitClassLabel(c.Exploit.Class, false))
		}
	}
	b.WriteString("\n")
}

// renderProductExploitPath explains why the vulnerability applies — or does
// not apply — to this product: the verified applicability facts, then the
// proven chain (data flows with proven origin, real call paths), the real
// falsifier for negative verdicts, or explicit uncertainty.
func renderProductExploitPath(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if isRU {
		b.WriteString("## Почему она применима / не применима к этому продукту\n\n")
	} else {
		b.WriteString("## Why it applies / does not apply to this product\n\n")
	}

	fmt.Fprintf(b, "%s\n\n", applicabilitySentence(c, isRU))

	v := domain.Verdict("")
	if c.Verdict != nil {
		v = c.Verdict.Verdict
	}
	switch v {
	case domain.VerdictNotAffected:
		// The applicability sentence already carries the verified cause.
	case domain.VerdictNoExploitPathFound:
		writeFalsifierLines(b, c, isRU)
	case domain.VerdictExploitable, domain.VerdictInconclusive:
		writeExploitChain(b, c, p, isRU)
	default:
		if isRU {
			b.WriteString("Оценка применимости и пути эксплуатации не завершена (вердикт не вынесен).\n\n")
		} else {
			b.WriteString("Applicability and exploit-path assessment did not complete (verdict not available).\n\n")
		}
	}
}

func applicabilitySentence(c *domain.AnalysisCase, isRU bool) string {
	mod, ver := moduleAndVersion(c)
	a := c.Affected
	if a == nil {
		if isRU {
			return "Применимость уязвимости к продукту не проверялась."
		}
		return "Vulnerability applicability to the product was not assessed."
	}
	if a.ModulePresent == domain.ClaimFalse {
		if isRU {
			return fmt.Sprintf("Модуль `%s` не входит в граф зависимостей продукта (проверено по `go list -m all`).", mod)
		}
		return fmt.Sprintf("Module `%s` is not part of the product dependency graph (verified via `go list -m all`).", mod)
	}
	if a.VersionAffected == domain.ClaimFalse {
		if isRU {
			return fmt.Sprintf("В продукте используется `%s` версии `%s`, которая находится вне уязвимого диапазона.", mod, ver)
		}
		return fmt.Sprintf("The product uses `%s` at version `%s`, which is outside the affected range.", mod, ver)
	}
	if a.PackagePresent == domain.ClaimFalse {
		if isRU {
			return fmt.Sprintf("Уязвимая версия `%s %s` присутствует в зависимостях, но уязвимые пакеты не входят в сборку: код не скомпилирован в продукт (`go list -deps`).", mod, ver)
		}
		return fmt.Sprintf("Affected version `%s %s` is present in dependencies, but the vulnerable packages are not in the build: the code is not linked into the product (`go list -deps`).", mod, ver)
	}
	if a.BuildRelevant == domain.ClaimFalse {
		if isRU {
			return fmt.Sprintf("Уязвимый пакет `%s` присутствует, но не компилируется для целевой платформы/конфигурации сборки.", mod)
		}
		return fmt.Sprintf("The affected package `%s` is present but does not compile for the target platform/build configuration.", mod)
	}
	if a.VersionAffected == domain.ClaimTrue {
		if isRU {
			return fmt.Sprintf("В продукте используется уязвимая версия `%s %s`.", mod, ver)
		}
		return fmt.Sprintf("The product uses the affected version `%s %s`.", mod, ver)
	}
	if len(a.PendingModules) > 0 {
		if isRU {
			return fmt.Sprintf("Модуль присутствует, но версию разрешить не удалось (`%s`): применимость не подтверждена и не опровергнута.", strings.Join(a.PendingModules, "`, `"))
		}
		return fmt.Sprintf("The module is present but its version could not be resolved (`%s`): applicability is neither confirmed nor falsified.", strings.Join(a.PendingModules, "`, `"))
	}
	if isRU {
		return "Применимость уязвимости к продукту не разрешена: часть проверок не завершена."
	}
	return "Vulnerability applicability is unresolved: some checks did not complete."
}

// writeExploitChain prints the verified chain evidence at its recorded
// scope: confirmed external-input flows (argument-scoped), the dependency
// reachability the call paths prove, and unproven flows named at their
// exact scope — never combined into a fabricated end-to-end payload proof.
// Confirmed flows and call-path reachability are distinct facts: showing
// one never suppresses the other.
func writeExploitChain(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	claims := claimByCondition(c)
	usage := moduleUsageIndex(c)

	var confirmed []string
	var unproven []string
	for _, f := range c.EvidenceGraph.DataFlows {
		// Receiver/object traces (Arg <= -2) stay in the audit: they do
		// not describe a payload argument and would read as contradictions
		// beside the argument-scoped facts.
		if f.Arg < -1 {
			continue
		}
		sinkRef := flowPointRef(c, p, f.Sink, usage)
		srcRef := flowPointRef(c, p, f.Source, usage)
		if f.PayloadUnproven || f.Origin == "" || f.Origin == domain.OriginUnknown {
			switch {
			case f.Arg >= 0:
				if isRU {
					unproven = append(unproven, fmt.Sprintf("обнаружен поток данных к аргументу %d в %s, но его внешнее происхождение не доказано", f.Arg, sinkRef))
				} else {
					unproven = append(unproven, fmt.Sprintf("a data flow reaches argument %d of %s, but the external origin of that value is not proven", f.Arg, sinkRef))
				}
			default:
				if isRU {
					unproven = append(unproven, fmt.Sprintf("обнаружен поток данных к %s из %s, но внешнее происхождение входа не доказано", sinkRef, srcRef))
				} else {
					unproven = append(unproven, fmt.Sprintf("a data flow to %s from %s was found, but the external origin of the input is not proven", sinkRef, srcRef))
				}
			}
			continue
		}
		if !externalOrigin(f.Origin) {
			// Known trusted/derived origin (constant, configuration,
			// generated, internal service, database): not attack-chain
			// evidence and not an unknown either.
			continue
		}
		var tx string
		if len(f.Transformations) > 0 {
			var names []string
			for _, t := range f.Transformations {
				n := t.Callee
				if n == "" {
					n = t.Function
				}
				names = append(names, "`"+n+"`")
			}
			if isRU {
				tx = fmt.Sprintf(" через %s", strings.Join(names, ", "))
			} else {
				tx = fmt.Sprintf(" via %s", strings.Join(names, ", "))
			}
		}
		// Scope the confirmed fact to exactly what was recorded: the
		// sink's argument position when the trace carried one.
		if isRU {
			switch {
			case f.Arg >= 0:
				confirmed = append(confirmed, fmt.Sprintf("внешние данные поступают в аргумент %d в %s%s", f.Arg, sinkRef, tx))
			case srcRef == sinkRef:
				confirmed = append(confirmed, fmt.Sprintf("внешние данные обрабатываются в %s%s", sinkRef, tx))
			default:
				confirmed = append(confirmed, fmt.Sprintf("данные из %s достигают %s%s", srcRef, sinkRef, tx))
			}
		} else {
			switch {
			case f.Arg >= 0:
				confirmed = append(confirmed, fmt.Sprintf("external input reaches argument %d in %s%s", f.Arg, sinkRef, tx))
			case srcRef == sinkRef:
				confirmed = append(confirmed, fmt.Sprintf("external data is processed in %s%s", sinkRef, tx))
			default:
				confirmed = append(confirmed, fmt.Sprintf("data from %s reaches %s%s", srcRef, sinkRef, tx))
			}
		}
	}
	confirmed = dedupeStrings(confirmed)
	unproven = dedupeStrings(unproven)
	if len(confirmed) > 3 {
		confirmed = confirmed[:3]
	}
	if len(unproven) > 2 {
		unproven = unproven[:2]
	}
	var paths []domain.CallPath
	for _, cp := range c.EvidenceGraph.CallPaths {
		if len(cp.Frames) > 0 {
			paths = append(paths, cp)
		}
	}

	missingCall := false
	for _, cond := range allConditions(c) {
		if cond.Kind != domain.ConditionMissingCall {
			continue
		}
		if cl, ok := claims[cond.ID]; ok && cl.Result == domain.ClaimTrue {
			missingCall = true
		}
	}

	if len(confirmed) > 0 {
		if isRU {
			b.WriteString("Подтверждённая обработка внешних данных (в пределах статического анализа):\n")
		} else {
			b.WriteString("Confirmed handling of external input (within static-analysis limits):\n")
		}
		for _, s := range confirmed {
			fmt.Fprintf(b, "- %s;\n", s)
		}
	}
	if len(paths) > 0 {
		if isRU {
			b.WriteString("Статический анализ подтвердил достижимость уязвимого символа (путь вызова доказывает достижимость, но не всю цепочку передачи внешних данных):\n")
		} else {
			b.WriteString("Static analysis confirmed reachability of the vulnerable symbol (a call path proves reachability, not the whole attacker-controlled flow):\n")
		}
		for i, cp := range paths {
			if i >= 2 {
				break
			}
			fmt.Fprintf(b, "- %s\n", callPathLine(cp, isRU))
		}
	}
	if missingCall {
		if isRU {
			b.WriteString("- Дефект — пропущенная обязательная проверка: проверено, что она отсутствует на активном пути исполнения.\n")
		} else {
			b.WriteString("- The defect is an omitted mandatory check: verified absent on an active execution pipeline.\n")
		}
	}
	if len(confirmed) == 0 && len(paths) == 0 && !missingCall {
		if isRU {
			b.WriteString("Сквозная подтверждённая цепочка от внешнего ввода к дефектной операции не построена.\n")
		} else {
			b.WriteString("No confirmed end-to-end chain from external input to the defective operation was established.\n")
		}
	}
	for _, s := range unproven {
		fmt.Fprintf(b, "- %s.\n", s)
	}
	b.WriteString("\n")
}

// moduleUsageIndex maps a recorded call site (file:line) to the module
// usage entry produced there, so a data-flow sink location can be named
// by the operation actually invoked (e.g. yaml.Unmarshal) rather than
// only by the enclosing product function.
func moduleUsageIndex(c *domain.AnalysisCase) map[string]domain.CallSite {
	idx := make(map[string]domain.CallSite, len(c.EvidenceGraph.ModuleUsages))
	for _, mu := range c.EvidenceGraph.ModuleUsages {
		if mu.File == "" || mu.Line <= 0 || mu.Callee == "" {
			continue
		}
		key := canonicalPath(mu.File).clean + "\x00" + strconv.Itoa(mu.Line)
		if _, ok := idx[key]; !ok {
			idx[key] = mu
		}
	}
	return idx
}

// flowCallee returns the invoked operation at a flow point: the recorded
// Callee, or the module usage observed at that exact site. CallSite.
// ModuleOwner is never consulted for the location of the enclosing file.
func flowCallee(cs domain.CallSite, usage map[string]domain.CallSite) string {
	if cs.Callee != "" {
		return cs.Callee
	}
	if cs.File == "" || cs.Line <= 0 {
		return ""
	}
	if mu, ok := usage[canonicalPath(cs.File).clean+"\x00"+strconv.Itoa(cs.Line)]; ok {
		return mu.Callee
	}
	return ""
}

// flowPointRef renders a data-flow endpoint: the invoked operation when
// known, else the enclosing function, plus its report-policy location.
func flowPointRef(c *domain.AnalysisCase, p reportPaths, cs domain.CallSite, usage map[string]domain.CallSite) string {
	name := flowCallee(cs, usage)
	if name == "" {
		name = cs.Function
	}
	loc := p.location(cs.File, cs.Package, cs.Line).Text
	if loc == "" {
		return fmt.Sprintf("`%s`", name)
	}
	return fmt.Sprintf("`%s` (`%s`)", name, loc)
}

func callPathLine(cp domain.CallPath, isRU bool) string {
	n := len(cp.Frames)
	var names []string
	addFrame := func(cs domain.CallSite) {
		name := cs.Function
		if cs.Package != "" {
			name = cs.Package + "." + cs.Function
		}
		if name == "" {
			name = cs.Callee
		}
		names = append(names, "`"+name+"`")
	}
	switch {
	case n <= 4:
		for _, f := range cp.Frames {
			addFrame(f)
		}
	default:
		addFrame(cp.Frames[0])
		addFrame(cp.Frames[1])
		names = append(names, "…")
		addFrame(cp.Frames[n-1])
	}
	if isRU {
		return fmt.Sprintf("путь вызова (%d кадров): %s", n, strings.Join(names, " → "))
	}
	return fmt.Sprintf("call path (%d frames): %s", n, strings.Join(names, " → "))
}

var falsifierRU = map[string]string{
	domain.FalsifierLocusPackageAbsent:       "пакеты дефектного кода не входят в граф сборки (`go list -deps`) — уязвимый код физически не скомпилирован",
	domain.FalsifierPackageAbsent:            "пакеты с заявленными символами не входят в граф сборки (`go list -deps`)",
	domain.FalsifierLocusFunctionUnreached:   "пакеты присутствуют в сборке, но вызовы уязвимых функций не обнаружены (отрицательная верификация выполнена)",
	domain.FalsifierGovulncheckSilence:       "статический анализ `govulncheck` не обнаружил путей вызова",
	domain.FalsifierNoModuleUsage:            "вызовов уязвимого модуля в коде продукта не обнаружено",
	domain.FalsifierUnreachedExportedSubject: "заявленный символ не вызывается из продукта",
	domain.FalsifierNoProductReader:          "читателей заявленного символа в коде продукта не обнаружено",
	domain.FalsifierMissingPairMember:        "обязательная пара вызовов не реализована полностью",
	domain.FalsifierSnapshotFactMismatch:     "факт снимка сборки противоречит условию",
	domain.FalsifierMissingSourceSymbol:      "заявленный символ отсутствует в исходниках зависимости",
	domain.FalsifierSafeConfigAssignment:     "конфигурационному параметру присваиваются только безопасные значения",
	domain.FalsifierZeroValueConfig:          "конфигурационный параметр никогда не присваивается — действует безопасное значение по умолчанию",
	domain.FalsifierSafeConfigKey:            "ключ конфигурации содержит безопасное значение",
	domain.FalsifierGuards:                   "условие нейтрализовано проверками (guards) в коде продукта",
	domain.FalsifierConstantOrGeneratedInput: "входные данные — константа или сгенерированное значение, не внешний ввод",
	domain.FalsifierLoopbackOnly:             "все разрешённые входящие привязки — loopback/unix/кластерные; публичная доступность опровергнута",
	domain.FalsifierConfigGatedOff:           "все пути вызова закрыты статически отключённой конфигурацией",
	domain.FalsifierProtocolRoleMismatch:     "требуемая роль протокола не совпадает с режимом работы продукта",
}

var falsifierEN = map[string]string{
	domain.FalsifierLocusPackageAbsent:       "the defect-locus packages are absent from the build graph (`go list -deps`) — the vulnerable code is not compiled",
	domain.FalsifierPackageAbsent:            "packages with the declared symbols are absent from the build graph (`go list -deps`)",
	domain.FalsifierLocusFunctionUnreached:   "the packages are linked, but no calls to the vulnerable functions were found (negative verification performed)",
	domain.FalsifierGovulncheckSilence:       "`govulncheck` static analysis found no call paths",
	domain.FalsifierNoModuleUsage:            "no calls into the vulnerable module were found in product code",
	domain.FalsifierUnreachedExportedSubject: "the declared symbol is not called from the product",
	domain.FalsifierNoProductReader:          "no readers of the declared symbol were found in product code",
	domain.FalsifierMissingPairMember:        "the mandatory call pair is not fully implemented",
	domain.FalsifierSnapshotFactMismatch:     "a build-snapshot fact contradicts the condition",
	domain.FalsifierMissingSourceSymbol:      "the declared symbol is absent from the dependency source",
	domain.FalsifierSafeConfigAssignment:     "the configuration knob is only assigned safe values",
	domain.FalsifierZeroValueConfig:          "the configuration knob is never assigned — the safe default applies",
	domain.FalsifierSafeConfigKey:            "the configuration key holds a safe value",
	domain.FalsifierGuards:                   "the condition is neutralized by guards in product code",
	domain.FalsifierConstantOrGeneratedInput: "the input is a constant or a generated value, not external input",
	domain.FalsifierLoopbackOnly:             "all resolved inbound binds are loopback/unix/cluster-internal; public exposure is falsified",
	domain.FalsifierConfigGatedOff:           "all call paths are gated by a statically disabled configuration flag",
	domain.FalsifierProtocolRoleMismatch:     "the required protocol role does not match the product's deployment mode",
}

func falsifierPhrase(kind string, isRU bool) string {
	if isRU {
		if s, ok := falsifierRU[kind]; ok {
			return s
		}
		return "условие опровергнуто детерминированной проверкой"
	}
	if s, ok := falsifierEN[kind]; ok {
		return s
	}
	return "the condition was falsified by a deterministic check"
}

func falsifierBasisPhrase(cl domain.Claim, isRU bool) string {
	switch cl.FalsifierBasis {
	case domain.BasisDeclaredTrust:
		if isRU {
			return " (основание — принятое допущение оператора о доверенной инфраструктуре, не проверка кода)"
		}
		return " (basis — an accepted operator assertion of trusted infrastructure, not code verification)"
	case domain.BasisAutoPerimeter:
		if isRU {
			return " (основание — обнаруженные атрибутированные deployment-артефакты кластерного периметра)"
		}
		return " (basis — detected attributed deployment artifacts of a cluster perimeter)"
	case domain.BasisConfigOrigin:
		if isRU {
			return " (основание — входы разрешаются в локальную конфигурацию хоста)"
		}
		return " (basis — inputs resolve to local host configuration)"
	}
	return ""
}

// writeFalsifierLines names the verified falsified mandatory conditions for a
// negative verdict: the real falsifier and its basis — never a bare
// "no path found".
func writeFalsifierLines(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	claims := claimByCondition(c)
	wrote := false
	for _, cond := range allConditions(c) {
		if !cond.Mandatory {
			continue
		}
		cl, ok := claims[cond.ID]
		if !ok || cl.Result != domain.ClaimFalse {
			continue
		}
		desc := conditionHumanDesc(cond, isRU)
		basis := falsifierPhrase(cl.Falsifier, isRU) + falsifierBasisPhrase(cl, isRU)
		if isRU {
			fmt.Fprintf(b, "- Обязательное условие «%s» опровергнуто: %s.\n", desc, basis)
		} else {
			fmt.Fprintf(b, "- Mandatory condition \"%s\" is falsified: %s.\n", desc, basis)
		}
		wrote = true
	}
	if !wrote {
		if isRU {
			b.WriteString("- Обязательное условие эксплуатации опровергнуто.\n")
		} else {
			b.WriteString("- A mandatory exploit condition was proven false.\n")
		}
	}
	b.WriteString("\n")
}

// renderConfirmedFacts lists only real TRUE / verified-FALSE results in
// human form — never claim/evidence ids, producers or raw enum values.
func renderConfirmedFacts(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if isRU {
		b.WriteString("## Что подтверждено\n\n")
	} else {
		b.WriteString("## Confirmed facts\n\n")
	}

	mod, ver := moduleAndVersion(c)
	var facts []string
	add := func(ru, en string) {
		msg := ru
		if !isRU {
			msg = en
		}
		for _, x := range facts {
			if x == msg {
				return
			}
		}
		facts = append(facts, msg)
	}

	if a := c.Affected; a != nil {
		switch {
		case a.ModulePresent == domain.ClaimTrue && ver != "":
			add(
				fmt.Sprintf("в сборке используется модуль `%s` версии `%s`", mod, ver),
				fmt.Sprintf("the build uses `%s` version `%s`", mod, ver))
		case a.ModulePresent == domain.ClaimTrue:
			add(
				fmt.Sprintf("уязвимый модуль `%s` входит в зависимости продукта", mod),
				fmt.Sprintf("the affected module `%s` is a product dependency", mod))
		case a.ModulePresent == domain.ClaimFalse:
			checked := strings.Join(a.CheckedModules, "`, `")
			if checked == "" {
				checked = mod
			}
			add(
				fmt.Sprintf("модуль(и) `%s` не входят в граф зависимостей продукта (`go list -m all`)", checked),
				fmt.Sprintf("module(s) `%s` are not part of the product dependency graph (`go list -m all`)", checked))
		}
		if ver != "" {
			switch {
			case a.VersionAffected == domain.ClaimTrue:
				add(
					fmt.Sprintf("версия `%s` модуля `%s` входит в уязвимый диапазон версий", ver, mod),
					fmt.Sprintf("version `%s` of `%s` falls inside the affected version range", ver, mod))
			case a.VersionAffected == domain.ClaimFalse:
				add(
					fmt.Sprintf("версия `%s` модуля `%s` находится вне уязвимого диапазона версий", ver, mod),
					fmt.Sprintf("version `%s` of `%s` is outside the affected version range", ver, mod))
			}
		}
		switch {
		case a.PackagePresent == domain.ClaimTrue:
			add(
				"уязвимый пакет входит в сборку продукта (`go list -deps`)",
				"the affected package is linked into the product build (`go list -deps`)")
		case a.PackagePresent == domain.ClaimFalse:
			checked := strings.Join(a.CheckedPackages, "`, `")
			if checked == "" {
				var paths []string
				for _, pkg := range c.Vulnerability.AffectedPackages {
					paths = append(paths, pkg.Path)
				}
				checked = strings.Join(paths, "`, `")
			}
			if checked != "" {
				add(
					fmt.Sprintf("уязвимые пакеты `%s` отсутствуют в транзитивном замыкании сборки (`go list -deps -test ./...`)", checked),
					fmt.Sprintf("affected packages `%s` are absent from the transitive import closure (`go list -deps -test ./...`)", checked))
			} else {
				add(
					"уязвимые пакеты отсутствуют в транзитивном замыкании сборки (`go list -deps`)",
					"affected packages are absent from the transitive import closure (`go list -deps`)")
			}
		}
		switch {
		case a.BuildRelevant == domain.ClaimTrue:
			add(
				fmt.Sprintf("уязвимый код компилируется для целевой платформы (%s/%s)", c.Product.GOOS, c.Product.GOARCH),
				fmt.Sprintf("the affected code compiles for the target platform (%s/%s)", c.Product.GOOS, c.Product.GOARCH))
		case a.BuildRelevant == domain.ClaimFalse:
			add(
				"уязвимый код не компилируется для целевой платформы (ограничен другими платформами или конфигурациями сборки)",
				"the affected code does not compile for the target platform (constrained to other platforms/build configurations)")
		}
	}

	if syms := sinkSymbols(c); len(syms) > 0 {
		var names []string
		for _, s := range syms {
			names = append(names, fmt.Sprintf("`%s.%s`", s.Package, s.Symbol))
		}
		if subjectPresenceProven(c, syms) {
			add(
				fmt.Sprintf("точка дефекта локализована в исходниках зависимости: %s", strings.Join(names, ", ")),
				fmt.Sprintf("the defect site is localized in the dependency source: %s", strings.Join(names, ", ")))
		} else {
			// Resolved only against advisory-listed names: no persisted
			// presence check, so these are declared affected entry points —
			// not an independently localized defect site.
			add(
				fmt.Sprintf("указанные в advisory уязвимые функции относятся к зависимости: %s", strings.Join(names, ", ")),
				fmt.Sprintf("the advisory-listed vulnerable functions belong to the dependency: %s", strings.Join(names, ", ")))
		}
	}

	if n := len(c.EvidenceGraph.CallPaths); n > 0 {
		var target string
		advisory := map[string]bool{}
		for _, s := range c.Vulnerability.AffectedSymbols {
			advisory[s.Package+"."+s.Symbol] = true
		}
		if c.Exploit != nil {
			for _, s := range c.Exploit.LocusSubjects {
				advisory[s.Package+"."+s.Symbol] = true
			}
		}
	outer:
		for _, cp := range c.EvidenceGraph.CallPaths {
			for _, f := range cp.Frames {
				if advisory[f.Package+"."+f.Function] {
					target = f.Package + "." + f.Function
					break outer
				}
			}
		}
		if target != "" {
			add(
				fmt.Sprintf("статический анализ вызовов (`govulncheck`) обнаружил путь вызова до `%s` (%d шт.)", target, n),
				fmt.Sprintf("static call analysis (`govulncheck`) found a call path to `%s` (%d total)", target, n))
		} else {
			add(
				fmt.Sprintf("статический анализ вызовов (`govulncheck`) обнаружил пути вызова к символам из advisory (%d шт.)", n),
				fmt.Sprintf("static call analysis (`govulncheck`) found call paths to advisory symbols (%d total)", n))
		}
	}

	flows := 0
	usage := moduleUsageIndex(c)
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.PayloadUnproven || !externalOrigin(f.Origin) || f.Arg < -1 {
			continue
		}
		add(
			fmt.Sprintf("внешние входные данные достигают %s", flowPointRef(c, p, f.Sink, usage)),
			fmt.Sprintf("externally controlled input reaches %s", flowPointRef(c, p, f.Sink, usage)))
		flows++
		if flows >= 2 {
			break
		}
	}

	listeners := 0
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction != "inbound" || f.Kind != "listener" {
			continue
		}
		loc := p.location(f.File, "", f.Line).Text
		if f.Address != "" {
			add(
				fmt.Sprintf("приложение создаёт входящий слушатель `%s` через `%s` (`%s`)", f.Address, f.Target, loc),
				fmt.Sprintf("the application opens an inbound listener `%s` via `%s` (`%s`)", f.Address, f.Target, loc))
		} else {
			add(
				fmt.Sprintf("приложение создаёт входящий слушатель через `%s` (`%s`)", f.Target, loc),
				fmt.Sprintf("the application opens an inbound listener via `%s` (`%s`)", f.Target, loc))
		}
		listeners++
		if listeners >= 2 {
			break
		}
	}

	// Mandatory condition results in human form: an "all confirmed" line
	// only when the model is non-empty and every mandatory condition is
	// TRUE; verified-FALSE conditions are positive negative facts.
	claims := claimByCondition(c)
	var mandatory []domain.Condition
	for _, cond := range allConditions(c) {
		if cond.Mandatory {
			mandatory = append(mandatory, cond)
		}
	}
	allTrue := len(mandatory) > 0
	for _, cond := range mandatory {
		cl, ok := claims[cond.ID]
		if !ok || cl.Result != domain.ClaimTrue {
			allTrue = false
			break
		}
	}
	if allTrue {
		add(
			"все обязательные условия эксплуатации подтверждены",
			"all mandatory exploit conditions are confirmed")
	} else {
		for _, cond := range mandatory {
			cl, ok := claims[cond.ID]
			if !ok {
				continue
			}
			desc := conditionHumanDesc(cond, isRU)
			switch cl.Result {
			case domain.ClaimTrue:
				add(
					fmt.Sprintf("условие подтверждено: «%s»", desc),
					fmt.Sprintf("condition confirmed: \"%s\"", desc))
			case domain.ClaimFalse:
				add(
					fmt.Sprintf("условие опровергнуто: «%s» (%s)", desc, falsifierPhrase(cl.Falsifier, isRU)),
					fmt.Sprintf("condition falsified: \"%s\" (%s)", desc, falsifierPhrase(cl.Falsifier, isRU)))
			}
		}
	}

	if len(facts) == 0 {
		if isRU {
			b.WriteString("Детерминированных подтверждений не зафиксировано — см. следующий раздел.\n\n")
		} else {
			b.WriteString("No deterministic confirmations were recorded — see the next section.\n\n")
		}
		return
	}
	for _, f := range facts {
		fmt.Fprintf(b, "- %s;\n", f)
	}
	b.WriteString("\n")
}

// subjectPresenceProven reports whether at least one listed sink symbol
// has a persisted presence check proving its declaration exists in the
// dependency source — a SymbolDecls entry or a TRUE claim for a
// symbol_present condition. Advisory listing alone does not qualify.
func subjectPresenceProven(c *domain.AnalysisCase, syms []domain.SymbolRef) bool {
	for _, s := range syms {
		if site, checked := c.EvidenceGraph.SymbolDeclFor(s.Package + "." + s.Symbol); checked && site != nil {
			return true
		}
	}
	claims := claimByCondition(c)
	for _, cond := range allConditions(c) {
		if cond.Params[domain.ParamCheck] != domain.CheckSymbolPresent {
			continue
		}
		for _, s := range syms {
			matched := false
			for _, subj := range cond.Subjects {
				if subj == s {
					matched = true
				}
			}
			if cond.Subject != nil && *cond.Subject == s {
				matched = true
			}
			if !matched {
				continue
			}
			if cl, ok := claims[cond.ID]; ok && cl.Result == domain.ClaimTrue {
				return true
			}
		}
	}
	return false
}

// renderUnknowns lists the concrete unresolved factors of this analysis and
// the explicit trust basis when a result depends on deployment assumptions,
// then the "what could change the assessment" block (never alternative
// verdicts).
func renderUnknowns(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if isRU {
		b.WriteString("## Что не удалось подтвердить\n\n")
	} else {
		b.WriteString("## What could not be confirmed\n\n")
	}

	claims := claimByCondition(c)
	usage := moduleUsageIndex(c)
	var unknowns []string
	add := func(ru, en string) {
		msg := ru
		if !isRU {
			msg = en
		}
		for _, x := range unknowns {
			if x == msg {
				return
			}
		}
		unknowns = append(unknowns, msg)
	}

	for _, cond := range allConditions(c) {
		if !cond.Mandatory {
			continue
		}
		cl, ok := claims[cond.ID]
		desc := conditionHumanDesc(cond, isRU)
		switch {
		case !ok:
			add(
				fmt.Sprintf("обязательное условие «%s» не проверялось (нет данных)", desc),
				fmt.Sprintf("mandatory condition \"%s\" was not evaluated (no data)", desc))
		case cl.Result == domain.ClaimUnknown:
			add(
				fmt.Sprintf("обязательное условие «%s» не разрешено", desc),
				fmt.Sprintf("mandatory condition \"%s\" is unresolved", desc))
		}
	}
	for _, cond := range allConditions(c) {
		if cond.Mandatory {
			continue
		}
		if cl, ok := claims[cond.ID]; ok && cl.Result == domain.ClaimUnknown {
			desc := conditionHumanDesc(cond, isRU)
			add(
				fmt.Sprintf("условие «%s» не разрешено", desc),
				fmt.Sprintf("condition \"%s\" is unresolved", desc))
		}
	}

	if c.Exploit != nil && len(c.Exploit.UnresolvedSubjects) > 0 {
		absent := map[domain.SymbolRef]bool{}
		for _, s := range c.Exploit.AbsentSubjects {
			absent[s] = true
		}
		var pending []string
		for _, s := range c.Exploit.UnresolvedSubjects {
			if absent[s] {
				continue
			}
			pending = append(pending, fmt.Sprintf("`%s.%s`", s.Package, s.Symbol))
		}
		if len(pending) > 0 {
			add(
				fmt.Sprintf("заявленные в advisory функции не разрешены в исходниках зависимости и не доказаны отсутствующими в сборке: %s", strings.Join(pending, ", ")),
				fmt.Sprintf("advisory-declared symbols unresolved in dependency source and not proven absent from the build: %s", strings.Join(pending, ", ")))
		}
	}

	// Unmodeled security-relevant transformations are a recorded analysis
	// boundary: the traced value passed through them but their effect on
	// the payload was never modeled — neither a mitigation nor evidence
	// the flaw still triggers.
	if names := unmodeledTransformNames(c); len(names) > 0 {
		joined := "`" + strings.Join(names, "`, `") + "`"
		add(
			fmt.Sprintf("на трассируемом пути встречаются преобразования данных, влияющие на безопасность, но не смоделированные как проверки: %s — их влияние на достижимость дефекта не оценено", joined),
			fmt.Sprintf("security-relevant data transformations on the traced path are not modeled as checks: %s — their effect on reaching the defect is unassessed", joined))
	}

	unproven := 0
	for _, f := range c.EvidenceGraph.DataFlows {
		if !f.PayloadUnproven && f.Origin != "" && f.Origin != domain.OriginUnknown {
			continue
		}
		if f.Arg < -1 {
			continue // receiver/output provenance stays in the audit
		}
		add(
			fmt.Sprintf("поток данных к %s обнаружен, но внешнее происхождение полезной нагрузки не доказано", flowPointRef(c, p, f.Sink, usage)),
			fmt.Sprintf("a data flow to %s was found, but the external origin of the payload is not proven", flowPointRef(c, p, f.Sink, usage)))
		unproven++
		if unproven >= 3 {
			break
		}
	}

	// Deployment coverage: relevant only while the result still depends on
	// the deployment context. A closed finding (DISMISSED) or a config-origin
	// verdict no longer raises an open deployment question.
	configOrigin := c.Verdict != nil && c.Verdict.GroundBasis == domain.BasisConfigOrigin
	deploymentOpen := c.ContextualRisk == nil ||
		c.ContextualRisk.TriageDisposition != domain.TriageDismissed
	if deploymentOpen && len(c.Product.DeployManifests) == 0 && c.Product.DeployArchive == "" && !configOrigin {
		var observed string
		for _, f := range c.EvidenceGraph.ExposuresList() {
			if f.Direction == "inbound" && f.Kind == "listener" {
				observed = f.Address
				if observed == "" {
					observed = f.Target
				}
				break
			}
		}
		if isRU {
			if observed != "" {
				add(fmt.Sprintf("по репозиторию определён только локальный факт: слушатель `%s`; фактический сетевой периметр production-развёртывания не определён", observed), "")
			} else {
				add("фактический сетевой периметр production-развёртывания по репозиторию не определён", "")
			}
			add("внешние ограничения доступа могут находиться вне анализируемых файлов (например, Kubernetes NetworkPolicy, Istio AuthorizationPolicy, Ingress / API Gateway, firewall)", "")
		} else {
			if observed != "" {
				add("", fmt.Sprintf("only a local fact was resolved from the repository: listener `%s`; the actual production deployment perimeter is undetermined", observed))
			} else {
				add("", "the actual production deployment perimeter could not be determined from the repository")
			}
			add("", "external access restrictions may live outside the analyzed files (e.g. Kubernetes NetworkPolicy, Istio AuthorizationPolicy, Ingress / API Gateway, firewall)")
		}
	}

	// Auth wiring without proven per-route coverage is a limitation, not a
	// control.
	if c.ContextualRisk != nil && c.ContextualRisk.Factors.Authentication == "REQUIRED" {
		covered := false
		for _, cond := range allConditions(c) {
			if cond.Kind == domain.ConditionAuthn {
				if cl, ok := claims[cond.ID]; ok && cl.Result == domain.ClaimTrue {
					covered = true
				}
			}
		}
		if !covered {
			add(
				"обнаружена проверка аутентификации, но её покрытие всех маршрутов к уязвимой операции не подтверждено",
				"authentication wiring was detected, but its coverage of all routes to the vulnerable operation is not confirmed")
		}
	}

	if c.Justification != nil {
		for _, rem := range c.Justification.HumanRemainder {
			text := humanRemainderText(rem, isRU)
			if text != "" && !internalIDRe.MatchString(text) {
				add(p.text(text), p.text(text))
			}
		}
	}

	if len(unknowns) == 0 {
		if isRU {
			b.WriteString("По собранным данным неразрешённых факторов не зафиксировано.\n\n")
		} else {
			b.WriteString("No unresolved factors were recorded in the collected data.\n\n")
		}
	} else {
		for _, u := range unknowns {
			fmt.Fprintf(b, "- %s;\n", u)
		}
		b.WriteString("\n")
	}

	if basis := groundBasisRationale(c, isRU); basis != "" {
		fmt.Fprintf(b, "%s\n\n", basis)
	}

	renderAssessmentChanges(b, c, isRU)
}

// unmodeledTransformNames collects the security-relevant transformations
// that persisted claim limitations recorded as "not modeled as guards" —
// the boundary wording is generated here; only the callee list is reused.
func unmodeledTransformNames(c *domain.AnalysisCase) []string {
	var names []string
	for _, cl := range c.Claims {
		for _, lim := range cl.Limitations {
			idx := strings.Index(lim, "not modeled as guards")
			if idx < 0 {
				continue
			}
			colon := strings.Index(lim[idx:], ":")
			if colon < 0 {
				continue
			}
			for _, n := range strings.Split(lim[idx+colon+1:], ",") {
				if n = strings.TrimSpace(n); n != "" {
					names = append(names, n)
				}
			}
		}
	}
	return dedupeStrings(names)
}

// groundBasisRationale makes the trust basis of a NEPF verdict explicit in
// the human-readable report: a verdict resting on a declared or detected
// deployment trust boundary is an assumption, not a code-level proof, and
// must read as such.
func groundBasisRationale(c *domain.AnalysisCase, isRU bool) string {
	if c.Verdict == nil {
		return ""
	}
	switch c.Verdict.GroundBasis {
	case domain.BasisDeclaredTrust:
		if isRU {
			return "Основание вердикта: заявленная граница доверия развёртывания (`--trusted-peer`/`--perimeter`) — принятое допущение оператора о доверенности пиров и инфраструктуры, а не проверка кода; при смене условий деплоя вердикт требует пересмотра."
		}
		return "Verdict basis: declared deployment trust boundary (`--trusted-peer`/`--perimeter`) — an accepted operator assertion about trusted peers and infrastructure, not code verification; the verdict must be revisited if deployment conditions change."
	case domain.BasisAutoPerimeter:
		if isRU {
			return "Основание вердикта: автоматически определённый кластерный периметр по атрибутированным манифестам развёртывания (ClusterIP/mesh-изоляция); достоверность ограничена найденными манифестами — публичные маршруты вне сканированных файлов не учтены."
		}
		return "Verdict basis: automatically detected cluster perimeter from attributed deployment manifests (ClusterIP/mesh isolation); confidence is limited to the discovered manifests — public routes outside the scanned files are not covered."
	case domain.BasisConfigOrigin:
		if isRU {
			return "Основание вердикта: все отслеженные входы разрешаются в локальные файлы конфигурации хоста (доверенный источник данных) — подтверждённое происхождение данных, не сетевая изоляция."
		}
		return "Verdict basis: all tracked inputs resolve to local host configuration files (a trusted data source) — proven data origin, not network isolation."
	}
	return ""
}

// renderAssessmentChanges prints the "what could change the assessment"
// subsection for open findings: the observed context, the re-triage
// condition and (when deployment manifests were absent) the fixed scenario
// table. It never assigns verdicts to hypothetical environments.
func renderAssessmentChanges(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if c.Verdict == nil {
		return
	}
	if c.ContextualRisk != nil && c.ContextualRisk.Priority == domain.PriorityDismissed {
		return
	}

	var observed string
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction == "inbound" && f.Kind == "listener" {
			observed = f.Address
			if observed == "" {
				observed = f.Target
			}
			break
		}
	}
	if observed == "" && c.DetectedPerimeter != "" && c.DetectedPerimeter != domain.PerimeterUnknown {
		observed = localizePerimeter(c.DetectedPerimeter, isRU)
	}

	if isRU {
		b.WriteString("### Что может изменить оценку\n\n")
		if observed != "" {
			fmt.Fprintf(b, "Текущий вывод сделан для обнаруженного в коде контекста `%s`.\n\n", observed)
		} else {
			b.WriteString("Текущий вывод сделан при отсутствии данных о фактическом развёртывании.\n\n")
		}
		b.WriteString("Приоритет может быть пересмотрен, если для целевой среды будет подтверждено, что недоверенный клиент не имеет сетевого пути к уязвимой поверхности. Для этого можно предоставить deployment-манифесты (`--deploy-manifests`) или указать целевой периметр (`--perimeter`).\n\n")
		if len(c.Product.DeployManifests) == 0 && c.Product.DeployArchive == "" {
			b.WriteString("| Среда | Что подтвердить | Возможный эффект |\n")
			b.WriteString("|---|---|---|\n")
			b.WriteString("| Публичная среда | Применимость дополнительных ограничений доступа | Без доказанного mitigation исходная оценка не меняется |\n")
			b.WriteString("| Внутренний кластер | Недоверенные workloads не имеют пути к endpoint | Возможное снижение после проверки |\n")
			b.WriteString("| Только loopback/unix | Реальный bind и отсутствие иных доступных inbound surfaces | Возможное снижение после проверки |\n\n")
		}
	} else {
		b.WriteString("### What could change the assessment\n\n")
		if observed != "" {
			fmt.Fprintf(b, "The current conclusion was drawn for the context observed in code: `%s`.\n\n", observed)
		} else {
			b.WriteString("The current conclusion was drawn without data on the actual deployment.\n\n")
		}
		b.WriteString("The priority may be re-evaluated if it is confirmed for the target environment that untrusted clients have no network path to the vulnerable surface. Deployment manifests (`--deploy-manifests`) or an explicit target perimeter (`--perimeter`) can be provided for that.\n\n")
		if len(c.Product.DeployManifests) == 0 && c.Product.DeployArchive == "" {
			b.WriteString("| Environment | What to confirm | Possible effect |\n")
			b.WriteString("|---|---|---|\n")
			b.WriteString("| Public environment | Applicable access restrictions | Baseline unchanged without proven mitigation |\n")
			b.WriteString("| Internal cluster | No path from untrusted workloads to the endpoint | Possible lowering after verification |\n")
			b.WriteString("| Loopback/unix only | Actual bind and no other accessible inbound surfaces | Possible lowering after verification |\n\n")
		}
	}
}

// renderTriageDecision renders base severity/source, baseline priority,
// effective priority and the human disposition. Internal statuses, SLA and
// contextual score stay in the audit report.
func renderTriageDecision(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if isRU {
		b.WriteString("## Оценка и приоритет\n\n")
	} else {
		b.WriteString("## Assessment and priority\n\n")
	}

	r := c.ContextualRisk
	if r == nil {
		if isRU {
			b.WriteString("Оценка не выполнена: вердикт не вынесен.\n\n")
		} else {
			b.WriteString("No assessment was performed: verdict not available.\n\n")
		}
		return
	}

	if isRU {
		fmt.Fprintf(b, "- **Исходная критичность:** %s\n", baseSeverityText(c, true))
		fmt.Fprintf(b, "- **Источник оценки:** %s\n", sourceText(c, true))
		fmt.Fprintf(b, "- **Исходный приоритет:** %s\n", priorityText(effectiveBasePriority(c), true))
		fmt.Fprintf(b, "- **Итоговый приоритет:** %s\n", priorityText(r.Priority, true))
	} else {
		fmt.Fprintf(b, "- **Baseline severity:** %s\n", baseSeverityText(c, false))
		fmt.Fprintf(b, "- **Assessment source:** %s\n", sourceText(c, false))
		fmt.Fprintf(b, "- **Baseline priority:** %s\n", priorityText(effectiveBasePriority(c), false))
		fmt.Fprintf(b, "- **Effective priority:** %s\n", priorityText(r.Priority, false))
	}

	var decision string
	switch r.TriageDisposition {
	case domain.TriageUnchanged:
		if isRU {
			decision = "без изменения"
		} else {
			decision = "unchanged"
		}
	case domain.TriageLowered:
		if isRU {
			decision = "приоритет снижен"
		} else {
			decision = "priority lowered"
		}
	case domain.TriageDismissed:
		if isRU {
			decision = "finding можно закрыть"
		} else {
			decision = "the finding can be closed"
		}
	case domain.TriageInconclusive:
		if isRU {
			decision = "требуется дополнительная проверка; исходный приоритет сохранён"
		} else {
			decision = "additional verification required; baseline priority retained"
		}
	default:
		if isRU {
			decision = "исходный приоритет сохранён"
		} else {
			decision = "baseline priority retained"
		}
	}
	if isRU {
		fmt.Fprintf(b, "- **Решение триажа:** %s.\n\n", decision)
	} else {
		fmt.Fprintf(b, "- **Triage decision:** %s.\n\n", decision)
	}

	// "Why lowered" appears only when the disposition is LOWERED and the
	// priority actually moved — saturated downgrades get no such block.
	if r.TriageDisposition == domain.TriageLowered && r.Priority != effectiveBasePriority(c) {
		if isRU {
			b.WriteString("### Почему приоритет снижен\n\n")
		} else {
			b.WriteString("### Why the priority was lowered\n\n")
		}
		if r.AdjustmentReason != "" {
			fmt.Fprintf(b, "- %s\n", p.text(r.AdjustmentReason))
		}
		if isRU {
			b.WriteString("- Снижение действительно для подтверждённых условий текущей среды; при изменении развёртывания требуется повторный триаж.\n\n")
		} else {
			b.WriteString("- The lowering is valid for the confirmed conditions of the current environment; re-triage is required if the deployment changes.\n\n")
		}
	}
}

// renderRemediation renders a short actionable fix recommendation per
// verdict. The H2 is always present; compensating controls are never
// presented as a fix.
func renderRemediation(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if isRU {
		b.WriteString("## Рекомендация по исправлению\n\n")
	} else {
		b.WriteString("## Remediation recommendation\n\n")
	}

	v := domain.Verdict("")
	if c.Verdict != nil {
		v = c.Verdict.Verdict
	}
	rem := p.text(remediation(c, isRU))

	switch v {
	case domain.VerdictNotAffected:
		if isRU {
			b.WriteString("Срочного исправления не требуется: уязвимость не применима к данной сборке.\n\n")
		} else {
			b.WriteString("No urgent fix is required: the vulnerability does not apply to this build.\n\n")
		}
		if rem != "" {
			if isRU {
				fmt.Fprintf(b, "\nОбновление зависимости можно выполнить в рамках регулярного цикла:\n\n%s\n\n", rem)
			} else {
				fmt.Fprintf(b, "\nThe dependency update can be done within the regular cycle:\n\n%s\n\n", rem)
			}
		}
	case domain.VerdictNoExploitPathFound:
		if isRU {
			b.WriteString("При подтверждённых условиях finding можно закрыть.\n\n")
		} else {
			b.WriteString("Under the verified conditions the finding can be closed.\n\n")
		}
		if rem != "" {
			if isRU {
				fmt.Fprintf(b, "\nОбновление зависимости остаётся плановой работой по остаточному риску:\n\n%s\n\n", rem)
			} else {
				fmt.Fprintf(b, "\nThe dependency update remains planned residual-dependency work:\n\n%s\n\n", rem)
			}
		}
	case domain.VerdictExploitable:
		if rem != "" {
			if isRU {
				fmt.Fprintf(b, "Требуется исправление.\n\n%s\n\n", rem)
			} else {
				fmt.Fprintf(b, "A fix is required.\n\n%s\n\n", rem)
			}
		} else {
			if isRU {
				b.WriteString("Опубликованного исправления нет или модуль не определён. Компенсирующие меры могут снизить риск, но не заменяют исправление зависимости.\n\n")
			} else {
				b.WriteString("No published fix exists or the module is undetermined. Compensating controls may reduce risk but do not replace fixing the dependency.\n\n")
			}
		}
	case domain.VerdictInconclusive:
		if rem != "" {
			if isRU {
				fmt.Fprintf(b, "Однозначный вывод не сделан. Допустимо безопасное обновление зависимости, а открытые вопросы из раздела «Что не удалось подтвердить» нужно закрыть:\n\n%s\n\n", rem)
			} else {
				fmt.Fprintf(b, "No definitive conclusion was reached. A safe dependency upgrade is acceptable, and the open questions in \"What could not be confirmed\" should be resolved:\n\n%s\n\n", rem)
			}
		} else {
			if isRU {
				b.WriteString("Однозначный вывод не сделан: сначала закройте открытые вопросы из раздела «Что не удалось подтвердить».\n\n")
			} else {
				b.WriteString("No definitive conclusion was reached: resolve the open questions in \"What could not be confirmed\" first.\n\n")
			}
		}
	default:
		if isRU {
			b.WriteString("Рекомендация будет сформирована после завершения анализа (вердикт не вынесен).\n\n")
		} else {
			b.WriteString("A recommendation will be produced once the analysis completes (verdict not available).\n\n")
		}
	}
}

// llmUsed reports whether LLM analysis was actually performed in this run:
// a positive call counter or a persisted LLM artifact. Configuration
// (CVEAnalysisProfile) and derived documents (Justification) do not count.
func llmUsed(c *domain.AnalysisCase) bool {
	return c.UsageSnapshot().LLMCalls > 0 ||
		c.CVEAnalysis != nil ||
		c.SemanticReview != nil ||
		c.StrategyPlan != nil
}

// renderAIUsage states honestly whether LLM analysis ran, which tasks it
// performed, which conclusions were proposed/accepted/rejected and what was
// deterministically verified. An LLM conclusion alone never grounds a
// negative verdict.
func renderAIUsage(b *strings.Builder, c *domain.AnalysisCase, p reportPaths, isRU bool) {
	if isRU {
		b.WriteString("## Использование AI\n\n")
	} else {
		b.WriteString("## AI usage\n\n")
	}

	if !llmUsed(c) {
		if isRU {
			b.WriteString("LLM-анализ в данном запуске не выполнялся.\n\nВсе выводы основаны на детерминированных проверках и статическом анализе.\n\n")
		} else {
			b.WriteString("No LLM analysis was performed in this run.\n\nAll conclusions are based on deterministic checks and static analysis.\n\n")
		}
		return
	}

	usage := c.UsageSnapshot()

	// 1. What the LLM was asked to do.
	if isRU {
		b.WriteString("**Что делала LLM:**\n")
	} else {
		b.WriteString("**What the LLM did:**\n")
	}
	wrote := false
	if c.CVEAnalysis != nil {
		wrote = true
		if isRU {
			b.WriteString("- исследовала механизм уязвимости по advisory и исправляющему коммиту\n")
		} else {
			b.WriteString("- researched the vulnerability mechanism against the advisory and the fix commit\n")
		}
	}
	if c.StrategyPlan != nil {
		wrote = true
		if isRU {
			fmt.Fprintf(b, "- предложила план проверки (`%s`)\n", p.text(localizedText(c, c.StrategyPlan.SelectedStrategy, isRU)))
		} else {
			fmt.Fprintf(b, "- proposed a verification plan (`%s`)\n", p.text(c.StrategyPlan.SelectedStrategy))
		}
	}
	if c.SemanticReview != nil {
		wrote = true
		if isRU {
			b.WriteString("- независимо рецензировала предложенный механизм\n")
		} else {
			b.WriteString("- independently reviewed the proposed mechanism\n")
		}
	}
	if usage.LLMCalls > 0 && !wrote {
		if isRU {
			fmt.Fprintf(b, "- зарегистрировано LLM-вызовов: %d, но привязанные артефакты анализа в кейсе не сохранены — состав задач не восстановить\n", usage.LLMCalls)
		} else {
			fmt.Fprintf(b, "- %d LLM call(s) recorded, but no attributed analysis artifacts are persisted in the case — the task breakdown cannot be reconstructed\n", usage.LLMCalls)
		}
	} else if usage.LLMCalls > 0 {
		if isRU {
			fmt.Fprintf(b, "- всего LLM-вызовов: %d\n", usage.LLMCalls)
		} else {
			fmt.Fprintf(b, "- total LLM calls: %d\n", usage.LLMCalls)
		}
	}
	b.WriteString("\n")

	// 2. What the LLM proposed (its own artifacts only).
	if isRU {
		b.WriteString("**Что предложила LLM:**\n")
	} else {
		b.WriteString("**What the LLM proposed:**\n")
	}
	wrote = false
	if c.CVEAnalysis != nil {
		for _, m := range c.CVEAnalysis.Mechanisms {
			if m.Summary == "" {
				continue
			}
			wrote = true
			fmt.Fprintf(b, "- %s\n", p.text(localizedText(c, m.Summary, isRU)))
		}
	}
	if c.SemanticReview != nil {
		for _, f := range c.SemanticReview.Findings {
			wrote = true
			fmt.Fprintf(b, "- %s\n", p.text(localizedText(c, f, isRU)))
		}
	}
	if !wrote {
		if isRU {
			b.WriteString("- содержательных предложений не зафиксировано\n")
		} else {
			b.WriteString("- no substantive proposals recorded\n")
		}
	}
	b.WriteString("\n")

	// 3. Per-mechanism disposition: for each proposal assertion, what the
	// deterministic layer confirmed, refuted, or could not check.
	// Adoption (a site entering the model) is separate from proof.
	if isRU {
		b.WriteString("**Что подтвердил или опроверг код по предложениям LLM:**\n")
	} else {
		b.WriteString("**What the code confirmed or refuted about the LLM proposals:**\n")
	}
	if len(c.ProposalVerifications) == 0 {
		if isRU {
			b.WriteString("- результаты проверки предложений не сохранены в этом кейсе (кейс без новой схемы атрибуции)\n")
		} else {
			b.WriteString("- per-proposal check results were not persisted in this case (no attribution records)\n")
		}
		b.WriteString("\n")
	} else {
		for _, m := range mechanismDispositions(c, isRU) {
			fmt.Fprintf(b, "- %s\n", p.text(m))
		}
		b.WriteString("\n")
	}

	// 4. Model adoption of LLM candidates (membership, not proof).
	if isRU {
		b.WriteString("**Что из предложенного LLM принято в модель:**\n")
	} else {
		b.WriteString("**Adopted into the model:**\n")
	}
	wrote = false
	seenAdopted := map[string]bool{}
	if c.RootCause != nil {
		rootCauses := append(append([]domain.RootCause{}, c.RootCause.RootCauses...), c.RootCause.Alternatives...)
		for _, rc := range rootCauses {
			if rc.Proposal == nil || rc.Proposal.Source != domain.ProposalSourceRootCause {
				continue
			}
			key := rc.Package + "." + rc.Symbol
			if seenAdopted[key] {
				continue
			}
			seenAdopted[key] = true
			wrote = true
			if isRU {
				fmt.Fprintf(b, "- кандидат `%s.%s` принят в модель\n", rc.Package, rc.Symbol)
			} else {
				fmt.Fprintf(b, "- candidate `%s.%s` adopted into the model\n", rc.Package, rc.Symbol)
			}
		}
	}
	if !wrote {
		if isRU {
			b.WriteString("- нет: ни одно предложение LLM не было принято в модель\n")
		} else {
			b.WriteString("- none: no LLM proposal was adopted into the model\n")
		}
	}
	b.WriteString("\n")

	// 5. LLM opinions and non-results (never deterministic evidence).
	if isRU {
		b.WriteString("**Мнение LLM и несостоявшиеся результаты:**\n")
	} else {
		b.WriteString("**LLM opinions and unusable results:**\n")
	}
	wrote = false
	if c.SemanticReview != nil {
		wrote = true
		if c.SemanticReview.Passed {
			if isRU {
				b.WriteString("- семантическая рецензия LLM: возражений к предложенному механизму не сообщила (это мнение LLM, не детерминированное доказательство)\n")
			} else {
				b.WriteString("- LLM semantic review reported no objection to the proposed mechanism (an LLM opinion, not deterministic proof)\n")
			}
		} else {
			if isRU {
				b.WriteString("- семантическая рецензия LLM: предложенный механизм не прошёл рецензию\n")
			} else {
				b.WriteString("- LLM semantic review: the proposed mechanism did not pass review\n")
			}
		}
	}
	if c.StrategyPlan != nil {
		wrote = true
		if isRU {
			b.WriteString("- план проверки LLM — предложение, а не выполненные проверки\n")
		} else {
			b.WriteString("- the LLM verification plan is a proposal, not executed checks\n")
		}
	}
	if c.Localization != nil && c.Localization.Model != "" {
		wrote = true
		if isRU {
			fmt.Fprintf(b, "- перевод прозы на русский выполнен моделью `%s` (только представление, факты не менялись)\n", c.Localization.Model)
		} else {
			fmt.Fprintf(b, "- Russian prose translation was performed by model `%s` (presentation only, no facts changed)\n", c.Localization.Model)
		}
	}
	if !wrote {
		if isRU {
			b.WriteString("- нет\n")
		} else {
			b.WriteString("- none\n")
		}
	}
	b.WriteString("\n")

	if isRU {
		b.WriteString("LLM-выводы — это гипотезы: они не заменяют детерминированные доказательства и не являются основанием отрицательного вердикта сами по себе.\n\n")
	} else {
		b.WriteString("LLM conclusions are hypotheses: they do not replace deterministic evidence and never ground a negative verdict by themselves.\n\n")
	}

	if isRU {
		b.WriteString("Ни один отрицательный вердикт не основан только на выводе LLM.\n\n")
	} else {
		b.WriteString("No negative verdict is based solely on an LLM conclusion.\n\n")
	}
}

// mechanismDispositions renders, per proposal mechanism, one human line
// stating exactly what each deterministic check established: symbol
// existence, product reachability, and which assertions have no checker
// (semantic role / whole mechanism). It uses only persisted
// ProposalVerification records — it never invents an outcome, and it never
// prints a raw English Detail into the Russian report.
func mechanismDispositions(c *domain.AnalysisCase, isRU bool) []string {
	type acc struct {
		existsTrue, existsFalse  []string
		reachTrue, reachFalse    []string
		roleUnknown, mechUnknown []string
	}
	order := []string{}
	byMech := map[string]*acc{}
	subjectName := func(rec domain.ProposalVerification, backtick bool) string {
		name := rec.SiteText
		if rec.Subject != nil {
			name = rec.Subject.Package + "." + rec.Subject.Symbol
		}
		if backtick && name != "" {
			return "`" + name + "`"
		}
		return name
	}
	for _, rec := range c.ProposalVerifications {
		key := rec.Proposal.ID + "#" + rec.Proposal.MechanismID
		if _, ok := byMech[key]; !ok {
			byMech[key] = &acc{}
			order = append(order, key)
		}
		a := byMech[key]
		name := subjectName(rec, true)
		switch rec.Check {
		case domain.CheckSymbolExists:
			if rec.Result == domain.ClaimTrue {
				a.existsTrue = append(a.existsTrue, name)
			} else {
				// FALSE (typed absence) and UNKNOWN (unresolvable text) both
				// mean existence was not established — keep them apart only
				// via wording, never as a confirmed fact.
				a.existsFalse = append(a.existsFalse, name)
			}
		case domain.CheckProductReachable:
			if rec.Result == domain.ClaimTrue {
				a.reachTrue = append(a.reachTrue, name)
			} else {
				a.reachFalse = append(a.reachFalse, name)
			}
		case domain.CheckSiteRole:
			if rec.Result == domain.ClaimUnknown {
				a.roleUnknown = append(a.roleUnknown, name)
			}
		case domain.CheckMechanism:
			if rec.Result == domain.ClaimUnknown {
				a.mechUnknown = append(a.mechUnknown, "")
			}
		}
	}

	var out []string
	for _, key := range order {
		a := byMech[key]
		var parts []string
		add := func(ru, en string) {
			if isRU {
				parts = append(parts, ru)
			} else {
				parts = append(parts, en)
			}
		}
		uniq := func(in []string) []string { return dedupeStrings(in) }
		if v := uniq(a.existsTrue); len(v) > 0 {
			add("объявления функций найдены в исходниках зависимости: "+strings.Join(v, ", "),
				"function declarations found in the dependency source: "+strings.Join(v, ", "))
		}
		if v := uniq(a.existsFalse); len(v) > 0 {
			add("объявления не найдены или не разрешены по исходникам: "+strings.Join(v, ", "),
				"declarations not found or not resolvable in the source: "+strings.Join(v, ", "))
		}
		if v := uniq(a.reachTrue); len(v) > 0 {
			add("сохранённый статический путь вызова достигает: "+strings.Join(v, ", "),
				"a persisted static call path reaches: "+strings.Join(v, ", "))
		}
		if v := uniq(a.reachFalse); len(v) > 0 {
			add("достижимость не доказана для: "+strings.Join(v, ", "),
				"reachability not established for: "+strings.Join(v, ", "))
		}
		if v := uniq(a.roleUnknown); len(v) > 0 {
			add(fmt.Sprintf("семантическая роль (выполняет ли функция дефектную операцию или только передаёт данные) не проверена автоматически: %s — наличие и достижимость функции роль не доказывают", strings.Join(v, ", ")),
				fmt.Sprintf("semantic role (does the function execute the defect or only forward data) was not checked automatically: %s — existence and reachability do not prove the role", strings.Join(v, ", ")))
		}
		if len(a.mechUnknown) > 0 {
			add("сам механизм дефекта не подтверждён и не опровергнут детерминированно (нет соответствующей проверки)",
				"the defect mechanism itself was neither confirmed nor refuted deterministically (no such checker)")
		}
		if len(parts) == 0 {
			continue
		}
		id := key
		if i := strings.IndexByte(key, '#'); i >= 0 {
			id = key[i+1:]
		}
		if id == "" {
			id = key
		}
		out = append(out, fmt.Sprintf("`%s`: %s", id, strings.Join(parts, "; ")))
	}
	if len(out) == 0 {
		if isRU {
			out = append(out, "ни одна проверка предложений не дала результата")
		} else {
			out = append(out, "no proposal check produced a result")
		}
	}
	return out
}

// humanRemainderText renders a human-readable obligation. Typed auxiliary
// site obligations get a deterministic RU/EN template (the persisted
// Question may be RU-only); other legacy questions are preserved verbatim.
func humanRemainderText(rem domain.HumanRemainderItem, isRU bool) string {
	if rem.Obligation == "verify_auxiliary_symbol" {
		name := rem.Question
		if rem.Subject != nil {
			name = fmt.Sprintf("`%s.%s`", rem.Subject.Package, rem.Subject.Symbol)
		}
		if isRU {
			return fmt.Sprintf("LLM предположила, что %s — вспомогательная функция. По исходникам уязвимой версии и исправляющему патчу определите роль функции: выполняет ли она дефектную операцию или только передаёт данные другой функции. До такой проверки исключать её из набора потенциально дефектных функций нельзя.", name)
		}
		return fmt.Sprintf("The LLM proposed that %s is an auxiliary (non-faulting) function. Using the vulnerable version's sources and the fix patch, determine its role: does it execute the defective operation, or only forward data to another function? Until that check, it must not be excluded from the set of potentially faulting functions.", name)
	}
	return rem.Question
}

// renderAuditLink points to the technical audit file and the machine
// snapshot — no fabricated remote URLs.
func renderAuditLink(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	if isRU {
		b.WriteString("## Ссылка на технический аудит\n\n")
		b.WriteString("Полный технический аудит — claims, доказательства, потоки данных, журнал инструментов, машинные гипотезы и ограничения: [Технический аудит](report.audit.md). Полный машинный снимок кейса: [report.json](report.json).\n\n")
	} else {
		b.WriteString("## Technical audit link\n\n")
		b.WriteString("The full technical audit — claims, evidence, data flows, tool journal, machine hypotheses and limitations: [Technical audit](report.audit.en.md). The complete machine snapshot of the case: [report.json](report.json).\n\n")
	}
}

// TrackerRationale renders a concise human-readable justification ready for
// issue trackers: the verdict, applicability cause, defect essence, triage
// outcome and the fix — in the requested language (Russian by default).
func TrackerRationale(c *domain.AnalysisCase, lang ...string) string {
	ensureTriageAssessment(c)
	populateUpgradeCompatibility(c)
	isRU := isRussian(lang...)
	p := newReportPaths(c)
	var b strings.Builder

	v := domain.Verdict("")
	if c.Verdict != nil {
		v = c.Verdict.Verdict
	}
	mod, ver := moduleAndVersion(c)

	switch v {
	case domain.VerdictNoExploitPathFound:
		if isRU {
			fmt.Fprintf(&b, "Not Exploitable (уязвимость не эксплуатируется): %s.\n\n", falsifiedConditionDesc(c, true))
		} else {
			fmt.Fprintf(&b, "Not exploitable (no exploit path): %s.\n\n", falsifiedConditionDesc(c, false))
		}
	case domain.VerdictNotAffected:
		if isRU {
			fmt.Fprintf(&b, "Not Affected (уязвимость не применима): %s.\n\n", notAffectedCause(c, true))
		} else {
			fmt.Fprintf(&b, "Not affected: %s.\n\n", notAffectedCause(c, false))
		}
	case domain.VerdictExploitable:
		if isRU {
			fmt.Fprintf(&b, "Exploitable (уязвимость подтверждена): используется уязвимая версия `%s %s`, обязательные условия эксплуатации подтверждены.\n\n", mod, ver)
		} else {
			fmt.Fprintf(&b, "Exploitable (vulnerability confirmed): the affected version `%s %s` is in use and the mandatory exploit conditions are confirmed.\n\n", mod, ver)
		}
	case domain.VerdictInconclusive:
		if isRU {
			b.WriteString("Inconclusive (требуется дополнительная проверка): часть обязательных условий не разрешена; исходный приоритет сохранён.\n\n")
		} else {
			b.WriteString("Inconclusive (additional verification required): some mandatory conditions are unresolved; the baseline priority is retained.\n\n")
		}
	default:
		if isRU {
			b.WriteString("Анализ уязвимости не завершён (вердикт не вынесен).\n\n")
		} else {
			b.WriteString("The vulnerability analysis did not complete (verdict not available).\n\n")
		}
	}
	fmt.Fprintf(&b, "%s — %s\n\n", c.Vulnerability.ID, defectDescription(c, p, isRU))

	if r := c.ContextualRisk; r != nil && c.Verdict != nil {
		if isRU {
			fmt.Fprintf(&b, "Приоритет: %s (исходный: %s).\n\n",
				priorityText(r.Priority, true), priorityText(effectiveBasePriority(c), true))
		} else {
			fmt.Fprintf(&b, "Priority: %s (baseline: %s).\n\n",
				priorityText(r.Priority, false), priorityText(effectiveBasePriority(c), false))
		}
	}

	if rem := p.text(remediation(c, isRU)); rem != "" && v != domain.VerdictNotAffected {
		fmt.Fprintf(&b, "%s\n\n", rem)
	}

	// Enrich with the persisted justification dossier when present: the
	// architectural context and the open expert questions are part of the
	// honest remainder, so they belong in the tracker text.
	if c.Justification != nil {
		if c.Justification.TechnicalMechanism != "" && !internalIDRe.MatchString(c.Justification.TechnicalMechanism) {
			if isRU {
				fmt.Fprintf(&b, "**Архитектурный контекст уязвимости:**\n%s\n", p.text(c.Justification.TechnicalMechanism))
			} else {
				fmt.Fprintf(&b, "**Vulnerability architectural context:**\n%s\n", p.text(c.Justification.TechnicalMechanism))
			}
		}
		if len(c.Justification.HumanRemainder) > 0 {
			if isRU {
				b.WriteString("\n**Открытые вопросы для экспертного подтверждения:**\n")
			} else {
				b.WriteString("\n**Open questions for expert confirmation:**\n")
			}
			for _, rem := range c.Justification.HumanRemainder {
				text := humanRemainderText(rem, isRU)
				if text == "" || internalIDRe.MatchString(text) {
					continue
				}
				fmt.Fprintf(&b, "- %s\n", p.text(text))
			}
		}
	}

	return strings.TrimSpace(b.String()) + "\n"
}

func formatEnv(c *domain.AnalysisCase, isRU bool) string {
	var parts []string
	if c.Product.GoVersion != "" {
		parts = append(parts, "Go "+c.Product.GoVersion)
	}
	if c.Product.GOOS != "" && c.Product.GOARCH != "" {
		parts = append(parts, c.Product.GOOS+"/"+c.Product.GOARCH)
	}
	if len(c.Product.BuildTags) > 0 {
		if isRU {
			parts = append(parts, "теги: "+strings.Join(c.Product.BuildTags, ", "))
		} else {
			parts = append(parts, "tags: "+strings.Join(c.Product.BuildTags, ", "))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func moduleAndVersion(c *domain.AnalysisCase) (string, string) {
	mod := ""
	if c.Affected != nil && c.Affected.SelectedModule != "" {
		mod = c.Affected.SelectedModule
	}
	if mod == "" {
		mod = c.Vulnerability.Module
	}
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" && c.Affected != nil && len(c.Affected.CheckedModules) > 0 {
		mod = c.Affected.CheckedModules[0]
	}
	ver := ""
	if c.Affected != nil {
		ver = c.Affected.ResolvedVersion
	}
	return mod, ver
}

// FixTarget picks the smallest published fixed version above the
// resolved one. ok=false when the component is not affected or the
// module cannot be named; version="" with ok=true means no fix exists.
func FixTarget(c *domain.AnalysisCase) (module, version string, ok bool) {
	if c.Affected == nil || c.Affected.VersionAffected != domain.ClaimTrue {
		return "", "", false
	}
	mod := c.Vulnerability.Module
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" {
		return "", "", false
	}
	resolved := c.Affected.ResolvedVersion
	var best string
	for _, f := range c.Vulnerability.FixedVersions {
		fv := normalizeSemver(f)
		if fv == "" {
			continue
		}
		if resolved != "" && semver.Compare(fv, normalizeSemver(resolved)) <= 0 {
			continue
		}
		if best == "" || semver.Compare(fv, best) < 0 {
			best = fv
		}
	}
	return mod, best, true
}

// FixCompatibility checks whether upgrading from resolved to fixed version
// is a drop-in minor/patch replacement or requires a major version bump.
func FixCompatibility(resolved, fixed string) (dropIn bool, majorBump bool, ok bool) {
	r := normalizeSemver(resolved)
	f := normalizeSemver(fixed)
	if r == "" || f == "" {
		return false, false, false
	}
	majR := semver.Major(r)
	majF := semver.Major(f)
	if majF == majR {
		return true, false, true
	}
	return false, true, true
}

func populateUpgradeCompatibility(c *domain.AnalysisCase) {
	if c == nil || c.Affected == nil {
		return
	}
	_, fixed, ok := FixTarget(c)
	if !ok || fixed == "" {
		c.Affected.UpgradeDropIn = false
		c.Affected.UpgradeMajorBump = false
		return
	}
	dropIn, majorBump, compOk := FixCompatibility(c.Affected.ResolvedVersion, fixed)
	if compOk {
		c.Affected.UpgradeDropIn = dropIn
		c.Affected.UpgradeMajorBump = majorBump
	} else {
		c.Affected.UpgradeDropIn = false
		c.Affected.UpgradeMajorBump = false
	}
}

// remediation renders a deterministic fix recommendation: the smallest
// fixed version above the resolved one, plus the go command to apply it.
// Empty when the component is not affected or no fix is published.
func remediation(c *domain.AnalysisCase, langRU ...bool) string {
	isRU := len(langRU) > 0 && langRU[0]
	mod, best, ok := FixTarget(c)
	if !ok {
		return ""
	}
	populateUpgradeCompatibility(c)
	resolved := c.Affected.ResolvedVersion
	if best == "" {
		if isRU {
			return fmt.Sprintf("Для зависимости `%s` (текущая: `%s`) нет опубликованных версий с исправлением. "+
				"Рассмотрите возможность фиксации безопасной версии или наложения патча.", mod, resolved)
		}
		return fmt.Sprintf("No fixed version published for `%s` (current: `%s`). "+
			"Consider pinning an unaffected release or vendoring a patch.", mod, resolved)
	}

	var notice string
	if c.Affected != nil {
		if c.Affected.UpgradeDropIn {
			if isRU {
				notice = " (совместимо по SemVer: minor/patch, без изменения импортов)"
			} else {
				notice = " (SemVer drop-in: minor/patch, no import path changes)"
			}
		} else if c.Affected.UpgradeMajorBump {
			maj := semver.Major(normalizeSemver(best))
			if isRU {
				notice = fmt.Sprintf(" (Внимание: смена мажорной версии %s, требуются обновление путей импорта и адаптация API)", maj)
			} else {
				notice = fmt.Sprintf(" (Notice: major version bump to %s, import path changes and API adaptation required)", maj)
			}
		}
	}

	if isRU {
		return fmt.Sprintf("Обновите зависимость `%s` с `%s` до `%s`%s:\n\n```\ngo get %s@%s\ngo mod tidy\n```",
			mod, resolved, best, notice, mod, best)
	}
	return fmt.Sprintf("Update `%s` from `%s` to `%s`%s:\n\n```\ngo get %s@%s\ngo mod tidy\n```",
		mod, resolved, best, notice, mod, best)
}

// normalizeSemver maps "1.2.3"/"v1.2.3" onto canonical semver for compare.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func formatSeverityBadge(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "BLOCKER":
		return "🔴 **CRITICAL**"
	case "HIGH":
		return "🟠 **HIGH**"
	case "MEDIUM", "MODERATE":
		return "🟡 **MEDIUM**"
	case "LOW":
		return "🟢 **LOW**"
	case "NONE":
		return "⚪ **NONE**"
	default:
		return "⚪ **" + sev + "**"
	}
}

// formatTriagePriority renders the priority tier as a bare queue label.
// Human reports must not carry remediation timelines or SLA wording.
func formatTriagePriority(p domain.TriagePriority, isRU bool) string {
	switch p {
	case domain.PriorityP0:
		return "**P0**"
	case domain.PriorityP1:
		return "**P1**"
	case domain.PriorityP2:
		return "**P2**"
	case domain.PriorityP3:
		return "**P3**"
	case domain.PriorityDismissed:
		if isRU {
			return "**снят**"
		}
		return "**dismissed**"
	default:
		return "**" + string(p) + "**"
	}
}

func verdictBadge(v domain.Verdict) string {
	switch v {
	case domain.VerdictNoExploitPathFound, domain.VerdictNotAffected:
		return "🟢"
	case domain.VerdictExploitable:
		return "🔴"
	case domain.VerdictInconclusive:
		return "🟡"
	default:
		return "⚪"
	}
}

func localizePerimeter(p string, isRU bool) string {
	if !isRU {
		return p
	}
	switch p {
	case domain.PerimeterPublic:
		return "Публичный (public)"
	case domain.PerimeterClusterInternal:
		return "Внутрикластерный (cluster-internal)"
	case domain.PerimeterUnknown:
		return "Не определён (unknown)"
	default:
		return p
	}
}

func localizePerimeterRationale(rationale string, isRU bool) string {
	if !isRU || rationale == "" || rationale == "-" {
		return rationale
	}
	switch rationale {
	case "no deployment exposure facts resolved; defaulting to zero-trust":
		return "Факты сетевой конфигурации не обнаружены; по умолчанию применяется модель нулевого доверия (zero-trust)"
	case "no structural cluster-isolation evidence (ClusterIP service or loopback/unix-only listeners); defaulting to zero-trust":
		return "Структурные свидетельства изоляции внутри кластера отсутствуют (ClusterIP или только loopback/unix слушатели); по умолчанию применяется модель нулевого доверия (zero-trust)"
	case "ClusterIP service found":
		return "Обнаружен сервис ClusterIP"
	}

	res := rationale
	if strings.HasPrefix(res, "public exposure detected: ") {
		res = "Обнаружен публичный доступ: " + strings.TrimPrefix(res, "public exposure detected: ")
	} else if strings.HasPrefix(res, "cluster-internal perimeter: ") {
		res = "Внутрикластерный периметр: " + strings.TrimPrefix(res, "cluster-internal perimeter: ")
	} else if strings.HasPrefix(res, "unattributed external-routing manifests may front the service: ") {
		res = "Внешние маршрутизирующие манифесты без атрибуции могут обслуживать сервис: " + strings.TrimPrefix(res, "unattributed external-routing manifests may front the service: ")
	} else if strings.HasPrefix(res, "loopback/unix listeners present but inbound exposure unresolved: ") {
		res = "Обнаружены loopback/unix слушатели, но входящий сетевой периметр полностью не разрешён: " + strings.TrimPrefix(res, "loopback/unix listeners present but inbound exposure unresolved: ")
	} else if strings.HasPrefix(res, "unresolved inbound exposure: ") {
		res = "Неразрешённый входящий сетевой периметр: " + strings.TrimPrefix(res, "unresolved inbound exposure: ")
	}

	res = strings.ReplaceAll(res, "; no public ingress found", "; публичный ingress не обнаружен")
	res = strings.ReplaceAll(res, "; unresolved inbound surfaces bounded by declared service scope: ", "; неразрешённые входящие интерфейсы ограничены областью сервиса: ")
	res = strings.ReplaceAll(res, "inbound listener ", "входящий слушатель ")
	return res
}

// exploitClassLabel renders the inferred exploit class as a localized human
// label in the human report; the raw enum stays in audit/JSON. Unknown
// classes fall back to a localized "unclassified" phrase rather than the
// internal token.
func exploitClassLabel(class string, isRU bool) string {
	if isRU {
		if s, ok := exploitClassRU[class]; ok {
			return s
		}
		return "класс не установлен (" + class + ")"
	}
	if s, ok := exploitClassEN[class]; ok {
		return s
	}
	return "class not established (" + class + ")"
}

var exploitClassRU = map[string]string{
	"WIRE_PARSER":         "обработчик формата (парсер)",
	"OOB_WRITE":           "запись вне границ буфера",
	"INTEGER_OVERFLOW":    "целочисленное переполнение",
	"RESOURCE_EXHAUSTION": "истощение ресурсов",
	"NIL_DEREF":           "разыменование nil-указателя",
	"PATH_TRAVERSAL":      "обход пути (path traversal)",
	"INJECTION":           "инъекция",
	"DESERIALIZATION":     "десериализация",
	"INFO_LEAK":           "утечка информации",
	"SSRF":                "SSRF (серверный запрос от имени сервера)",
	"AUTH_BYPASS":         "обход аутентификации",
	"XXE":                 "XXE (внешние сущности XML)",
	"REDOS":               "ReDoS (отказ в обслуживании через регулярное выражение)",
	"RACE":                "состояние гонки",
	"URI_CONFUSION":       "неоднозначная обработка URI",
	"CONFIG_INJECTION":    "инъекция конфигурации",
	"CRYPTO_DOWNGRADE":    "понижение криптографической защиты",
}

var exploitClassEN = map[string]string{
	"WIRE_PARSER":         "wire-format parser flaw",
	"OOB_WRITE":           "out-of-bounds write",
	"INTEGER_OVERFLOW":    "integer overflow",
	"RESOURCE_EXHAUSTION": "resource exhaustion",
	"NIL_DEREF":           "nil dereference",
	"PATH_TRAVERSAL":      "path traversal",
	"INJECTION":           "injection",
	"DESERIALIZATION":     "deserialization",
	"INFO_LEAK":           "information leak",
	"SSRF":                "SSRF (server-side request forgery)",
	"AUTH_BYPASS":         "authentication bypass",
	"XXE":                 "XXE (XML external entity)",
	"REDOS":               "ReDoS (regular-expression denial of service)",
	"RACE":                "race condition",
	"URI_CONFUSION":       "URI confusion",
	"CONFIG_INJECTION":    "configuration injection",
	"CRYPTO_DOWNGRADE":    "cryptographic downgrade",
}

func sanitizeTableString(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.Join(strings.Fields(s), " ")
	if maxLen > 3 && len([]rune(s)) > maxLen {
		runes := []rune(s)
		return string(runes[:maxLen-3]) + "..."
	}
	return s
}

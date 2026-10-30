package risk

import (
	"math"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Assess evaluates the contextual risk and assigns a triage priority tier
// based on nominal severity and concrete product execution context.
func Assess(v domain.Vulnerability, c *domain.AnalysisCase, vr domain.VerdictResult) domain.ContextualRisk {
	baseSev := strings.ToUpper(strings.TrimSpace(v.BaseSeverity))
	baseScore := v.BaseScore
	if baseScore <= 0 {
		baseScore = defaultScoreForSeverity(baseSev)
	}
	if baseSev == "" {
		baseSev = defaultSeverityForScore(baseScore)
	}

	exposure := detectExposure(c)
	if exposure == "NONE" {
		// No exposure fact was resolved. That is UNKNOWN, not proof of
		// "no external exposure": an undiscovered listener is not a network
		// boundary, and the converse claim would be an overclaim.
		exposure = "UNKNOWN"
	}
	authn := detectAuthentication(c)

	factors := domain.RiskFactors{
		Verdict:        string(vr.Verdict),
		Exposure:       exposure,
		Authentication: authn,
		PayloadControl: "UNKNOWN",
		BlastRadius:    "UNKNOWN",
	}

	nomPrio := NominalPriority(baseSev, baseScore)

	// A failed assessment earned no verdict. It carries no safe or dismissed
	// disposition, because there is no conclusion to be safe about; the
	// nominal baseline is reported as a triage hint only.
	if vr.Verdict == "" {
		return domain.ContextualRisk{
			Status:           domain.RiskStatusUnassessed,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  domain.RiskLevelUnknown,
			Priority:         nomPrio,
			SLA:              "Manual Triage",
			AdjustmentReason: "Анализ не завершён: вердикт не вынесен, контекстная оценка риска не выполнялась. Указанный приоритет — номинальный (по базовой критичности), а не результат оценки.",
			Factors:          factors,
		}
	}

	// Rule 1: Dismissed (NOT_AFFECTED or NO_EXPLOIT_PATH_FOUND)
	if vr.Verdict == domain.VerdictNotAffected {
		return domain.ContextualRisk{
			Status:           domain.RiskStatusNotApplicable,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  domain.RiskLevelNone,
			ContextualScore:  0.0,
			Priority:         domain.PriorityDismissed,
			SLA:              "None",
			AdjustmentReason: "Применимость уязвимости в границах допущенного отрицательного доказательства опровергнута: уязвимый модуль, версия, пакет или реализация не входят в оцениваемую сборку либо исключены допущенным доказательством. Эксплуатация в этих границах невозможна; за их пределами вердикт ничего не утверждает. Блокировка сборки снята.",
			Factors:          factors,
		}
	}

	if vr.Verdict == domain.VerdictNoExploitPathFound {
		return domain.ContextualRisk{
			Status:           domain.RiskStatusAssessed,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  domain.RiskLevelNone,
			ContextualScore:  0.0,
			Priority:         domain.PriorityDismissed,
			SLA:              "None",
			AdjustmentReason: "Обязательное условие эксплуатации опровергнуто допущенным отрицательным доказательством (это может быть отсутствие уязвимого пути, недостижимость, конфигурация, происхождение входа, защитная проверка или граница доверия). Отсутствие уязвимого кода в сборке этим вердиктом не утверждается. Блокировка сборки снята.",
			Factors:          factors,
		}
	}

	// Rule 5: Inconclusive / Provisional
	if vr.Verdict == domain.VerdictInconclusive {
		prio := nomPrio
		if prio == domain.PriorityP0 {
			prio = domain.PriorityP1
		}
		lvl := defaultRiskLevelForScore(baseScore)
		if baseSev != "" {
			lvl = domain.RiskLevel(baseSev)
		}
		return domain.ContextualRisk{
			Status:           domain.RiskStatusProvisional,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  lvl,
			ContextualScore:  baseScore,
			Priority:         prio,
			SLA:              "Manual Triage",
			AdjustmentReason: "Условия эксплуатации не подтверждены и не опровергнуты; требуется ручной триаж входных данных и конфигурации.",
			Factors:          factors,
		}
	}

	// If verdict is EXPLOITABLE
	if vr.Verdict == domain.VerdictExploitable {
		// A library product has no deployment perimeter of its own: "no
		// listeners" describes the absence of a server in code that was
		// never meant to be one, not a network boundary protecting it.
		// Downgrading on that fact is a category error — the exploitability
		// boundary for a library is its public API, established elsewhere.
		if vr.ExploitabilityScope == domain.ScopeLibraryAPI {
			level := defaultRiskLevelForScore(baseScore)
			if baseSev != "" {
				level = domain.RiskLevel(baseSev)
			}
			return domain.ContextualRisk{
				Status:           domain.RiskStatusAssessed,
				BaseSeverity:     baseSev,
				BaseScore:        baseScore,
				ContextualLevel:  level,
				ContextualScore:  baseScore,
				Priority:         nomPrio,
				SLA:              slaForPriority(nomPrio),
				AdjustmentReason: "Область вывода — публичный API библиотеки: собственный сетевой периметр у библиотеки отсутствует, поэтому базовая оценка CVSS сохраняется. Эксплуатируемость конкретного приложения-потребителя зависит от того, передаёт ли оно внешние данные в этот API.",
				Factors:          factors,
			}
		}
		// Rule 2: Unmitigated (PUBLIC exposure without required authentication)
		// Strict invariant: neither score nor priority can escalate above baseline (nomPrio).
		// A Medium vulnerability without mitigations remains Medium / P2.
		if exposure == "PUBLIC" && authn != "REQUIRED" {
			level := defaultRiskLevelForScore(baseScore)
			if baseSev != "" {
				level = domain.RiskLevel(baseSev)
			}
			sla := slaForPriority(nomPrio)
			return domain.ContextualRisk{
				Status:           domain.RiskStatusAssessed,
				BaseSeverity:     baseSev,
				BaseScore:        baseScore,
				ContextualLevel:  level,
				ContextualScore:  baseScore,
				Priority:         nomPrio,
				SLA:              sla,
				AdjustmentReason: "Компенсационные меры в кодовой базе не обнаружены; базовая оценка CVSS подтверждена. Повышение критичности не производится.",
				Factors:          factors,
			}
		}

		// Rule 3: Mitigated by Authentication (PUBLIC exposure with authentication REQUIRED)
		if exposure == "PUBLIC" && authn == "REQUIRED" {
			score := math.Round(baseScore*0.75*10) / 10
			prio := DowngradePriority(nomPrio)
			return domain.ContextualRisk{
				Status:           domain.RiskStatusAssessed,
				BaseSeverity:     baseSev,
				BaseScore:        baseScore,
				ContextualLevel:  defaultRiskLevelForScore(score),
				ContextualScore:  score,
				Priority:         prio,
				SLA:              slaForPriority(prio),
				AdjustmentReason: "Снижение оценки: уязвимость достижима извне, но защищена предварительной аутентификацией/шлюзом (эксплуатация требует валидных учетных данных).",
				Factors:          factors,
			}
		}

		// Rule 4: Mitigated by a resolved internal network boundary. Only a
		// resolved loopback/unix bind may downgrade; an unresolved exposure
		// question is handled below and is never treated as a mitigation.
		if exposure == "INTERNAL" {
			score := math.Round(baseScore*0.5*10) / 10
			prio := DowngradePriority(DowngradePriority(nomPrio))
			return domain.ContextualRisk{
				Status:           domain.RiskStatusAssessed,
				BaseSeverity:     baseSev,
				BaseScore:        baseScore,
				ContextualLevel:  defaultRiskLevelForScore(score),
				ContextualScore:  score,
				Priority:         prio,
				SLA:              slaForPriority(prio),
				AdjustmentReason: "Снижение оценки: входящий слушатель привязан к локальному интерфейсу (127.0.0.1) либо к unix-сокету — сетевой доступ из внешней сети по этой точке исключён.",
				Factors:          factors,
			}
		}

		// No exposure fact resolved: the baseline stands and the report says
		// the question is open. "No listeners observed" is not a perimeter.
		level := defaultRiskLevelForScore(baseScore)
		if baseSev != "" {
			level = domain.RiskLevel(baseSev)
		}
		return domain.ContextualRisk{
			Status:           domain.RiskStatusAssessed,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  level,
			ContextualScore:  baseScore,
			Priority:         nomPrio,
			SLA:              slaForPriority(nomPrio),
			AdjustmentReason: "Факты о сетевой экспозиции не установлены: слушатели не обнаружены, но отсутствие внешнего доступа не доказано. Снижение оценки по сетевому периметру не применяется; базовая оценка CVSS сохраняется.",
			Factors:          factors,
		}
	}

	// Fallback for any other verdict
	return domain.ContextualRisk{
		Status:           domain.RiskStatusAssessed,
		BaseSeverity:     baseSev,
		BaseScore:        baseScore,
		ContextualLevel:  defaultRiskLevelForScore(baseScore),
		ContextualScore:  baseScore,
		Priority:         nomPrio,
		SLA:              slaForPriority(nomPrio),
		AdjustmentReason: "Автоматическая оценка риска завершена.",
		Factors:          factors,
	}
}

func slaForPriority(p domain.TriagePriority) string {
	switch p {
	case domain.PriorityP0:
		return "Immediate (Blocker)"
	case domain.PriorityP1:
		return "High Priority"
	case domain.PriorityP2:
		return "Scheduled"
	default:
		return "Low Priority"
	}
}

// NominalPriority derives the baseline triage priority from CVSS score / base severity.
// Priority can NEVER be escalated above this nominal priority.
func NominalPriority(baseSev string, baseScore float64) domain.TriagePriority {
	sev := strings.ToUpper(strings.TrimSpace(baseSev))
	switch {
	case sev == "CRITICAL" || sev == "BLOCKER" || baseScore >= 9.0:
		return domain.PriorityP0
	case sev == "HIGH" || baseScore >= 7.0:
		return domain.PriorityP1
	case sev == "MEDIUM" || sev == "MODERATE" || baseScore >= 4.0:
		return domain.PriorityP2
	case sev == "LOW" || baseScore > 0:
		return domain.PriorityP3
	default:
		return domain.PriorityP2
	}
}

// DowngradePriority lowers a triage priority tier by one level when mitigating controls are active.
func DowngradePriority(p domain.TriagePriority) domain.TriagePriority {
	switch p {
	case domain.PriorityP0:
		return domain.PriorityP1
	case domain.PriorityP1:
		return domain.PriorityP2
	case domain.PriorityP2:
		return domain.PriorityP3
	default:
		return domain.PriorityDismissed
	}
}

func detectExposure(c *domain.AnalysisCase) string {
	if c == nil {
		return "NONE"
	}

	var hasPublic, hasInternal bool

	// 1. Check Exposures in EvidenceGraph
	facts := c.EvidenceGraph.ExposuresList()
	for _, f := range facts {
		if f.Direction == "inbound" && f.Kind == "listener" {
			switch f.Scope {
			case domain.ScopeAllInterfaces, domain.ScopeHostSpecific:
				hasPublic = true
			case domain.ScopeLoopback, domain.ScopeUnix:
				hasInternal = true
			default:
				if strings.Contains(f.Address, "0.0.0.0") || strings.HasPrefix(f.Address, ":") {
					hasPublic = true
				} else if strings.Contains(f.Address, "127.0.0.1") || strings.Contains(f.Address, "localhost") {
					hasInternal = true
				}
			}
		}
	}

	// 2. Check Evidences in EvidenceGraph
	for _, ev := range c.EvidenceGraph.EvidenceList() {
		content := strings.ToLower(ev.Content)
		if ev.Kind == domain.EvidenceEntrypoint || strings.Contains(ev.Source, "exposure") || strings.Contains(ev.Source, "listener") {
			if strings.Contains(content, "0.0.0.0") || strings.Contains(content, "all-interfaces") {
				hasPublic = true
			} else if strings.Contains(content, "127.0.0.1") || strings.Contains(content, "localhost") || strings.Contains(content, "loopback") {
				hasInternal = true
			}
		}
	}

	if hasPublic {
		return "PUBLIC"
	}
	if hasInternal {
		return "INTERNAL"
	}
	return "NONE"
}

func detectAuthentication(c *domain.AnalysisCase) string {
	if c == nil {
		return "NONE"
	}

	// 1. Check Claims for authentication condition
	for _, cl := range c.Claims {
		cid := string(cl.ConditionID)
		if cl.Result == domain.ClaimTrue {
			if cid == "C-AUTH" || strings.Contains(strings.ToLower(cid), "auth") {
				return "REQUIRED"
			}
		}
	}

	// 2. Check Exposure facts for auth-middleware
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction == "inbound" && f.Kind == "auth-middleware" {
			return "REQUIRED"
		}
	}

	// 3. Check Evidence for auth-middleware
	for _, ev := range c.EvidenceGraph.EvidenceList() {
		if strings.Contains(strings.ToLower(ev.Content), "auth") && strings.Contains(strings.ToLower(ev.Content), "middleware") {
			return "REQUIRED"
		}
	}

	return "NONE"
}

func defaultScoreForSeverity(sev string) float64 {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "BLOCKER":
		return 9.8
	case "HIGH":
		return 7.5
	case "MEDIUM", "MODERATE":
		return 5.0
	case "LOW":
		return 3.0
	default:
		return 5.0
	}
}

func defaultSeverityForScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func defaultRiskLevelForScore(score float64) domain.RiskLevel {
	switch {
	case score >= 9.0:
		return domain.RiskLevelCritical
	case score >= 7.0:
		return domain.RiskLevelHigh
	case score >= 4.0:
		return domain.RiskLevelMedium
	case score > 0:
		return domain.RiskLevelLow
	case score == 0:
		return domain.RiskLevelNone
	default:
		return domain.RiskLevelUnknown
	}
}

package risk

import (
	"math"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Assess evaluates the contextual risk and assigns a triage priority tier
// based on nominal severity and concrete product execution context.
//
// Contextual analysis can only preserve, lower or dismiss the baseline: the
// returned priority is never more urgent than BasePriority, the level is
// never more severe than the baseline level and ContextualScore never
// exceeds BaseScore. Every result records the baseline it was clamped
// against (BasePriority) and what actually happened to it
// (TriageDisposition).
func Assess(v domain.Vulnerability, c *domain.AnalysisCase, vr domain.VerdictResult) domain.ContextualRisk {
	baseSev := strings.ToUpper(strings.TrimSpace(v.BaseSeverity))
	baseScore := v.BaseScore
	if baseScore <= 0 {
		baseScore = defaultScoreForSeverity(baseSev)
	}
	if baseSev == "" {
		baseSev = defaultSeverityForScore(baseScore)
	}

	baseLevel := nominalLevel(baseSev, baseScore)
	basePrio := NominalPriority(baseSev, baseScore)
	exposure, surfaces := classifyExposure(c)

	// Baseline result: the advisory's own severity/score/priority and the
	// unchanged disposition. Every verdict below is a candidate applied on
	// top of it and clamped back under it in the single finalization path.
	res := domain.ContextualRisk{
		Status:            domain.RiskStatusAssessed,
		BaseSeverity:      baseSev,
		BaseScore:         baseScore,
		BasePriority:      basePrio,
		TriageDisposition: domain.TriageUnchanged,
		ContextualLevel:   baseLevel,
		ContextualScore:   baseScore,
		Priority:          basePrio,
		SeveritySource:    v.SeveritySource,
		ScoreSource:       v.ScoreSource,
		Factors: domain.RiskFactors{
			Verdict:        string(vr.Verdict),
			Exposure:       exposure,
			Authentication: detectAuthentication(c),
			PayloadControl: "UNKNOWN",
			BlastRadius:    "UNKNOWN",
		},
	}

	// Candidate per verdict. lowerCandidate marks the only candidate that
	// may lower the priority: a proven loopback/unix isolation of every
	// inbound listener.
	candLevel, candScore, candPrio := baseLevel, baseScore, basePrio
	lowerCandidate := false
	switch {
	case vr.Verdict == domain.VerdictNotAffected:
		res.Status = domain.RiskStatusNotApplicable
		res.TriageDisposition = domain.TriageDismissed
		candLevel, candScore, candPrio = domain.RiskLevelNone, 0, domain.PriorityDismissed
		res.AdjustmentReason = "Вердикт NOT_AFFECTED: уязвимость неприменима к продукту по проверенным фактам; приоритет устранения снят."
	case vr.Verdict == domain.VerdictNoExploitPathFound:
		res.TriageDisposition = domain.TriageDismissed
		candLevel, candScore, candPrio = domain.RiskLevelNone, 0, domain.PriorityDismissed
		res.AdjustmentReason = "Вердикт NO_EXPLOIT_PATH_FOUND: обязательное условие эксплуатации опровергнуто проверенным falsifier с negative verification; приоритет устранения снят."
	case vr.Verdict == domain.VerdictExploitable:
		if surfaces.provenLoopbackOnly() {
			candScore = baseScore * 0.5
			candLevel = defaultRiskLevelForScore(candScore)
			candPrio = DowngradePriority(DowngradePriority(basePrio))
			lowerCandidate = true
		} else {
			res.AdjustmentReason = "Вердикт EXPLOITABLE: путь эксплуатации подтверждён, доказанных компенсирующих мер не зафиксировано; исходная оценка сохранена без усиления."
		}
	case vr.Verdict == domain.VerdictInconclusive, vr.Verdict == "":
		res.Status = domain.RiskStatusProvisional
		res.TriageDisposition = domain.TriageInconclusive
		res.AdjustmentReason = "Условия эксплуатации не подтверждены и не опровергнуты; требуется дополнительная проверка, исходные оценка и приоритет сохранены."
	default:
		res.Status = domain.RiskStatusProvisional
		res.TriageDisposition = domain.TriageInconclusive
		res.AdjustmentReason = "Финальный вердикт недоступен или неизвестен; исходные оценка и приоритет сохранены, требуется дополнительная проверка."
	}

	// Finalization: clamp the candidate back under the baseline.
	res.ContextualLevel = clampSeverity(candLevel, baseLevel)
	res.ContextualScore = clampScore(candScore, baseScore)
	res.Priority = clampPriority(candPrio, basePrio)
	if lowerCandidate {
		// LOWERED describes an actual priority change, not a score change:
		// under P3 saturation the priority is preserved and the disposition
		// stays UNCHANGED.
		if res.Priority != basePrio {
			res.TriageDisposition = domain.TriageLowered
			res.AdjustmentReason = "Понижение приоритета: подтверждено структурно, что все входящие слушатели привязаны только к loopback/unix-сокетам и иных доступных inbound-поверхностей нет."
		} else {
			res.TriageDisposition = domain.TriageUnchanged
			res.AdjustmentReason = "Подтверждено loopback/unix-ограничение входящего доступа; приоритет уже минимальный и дополнительно не снижается."
		}
	}
	switch res.TriageDisposition {
	case domain.TriageInconclusive:
		res.SLA = "Manual Triage"
	case domain.TriageDismissed:
		res.SLA = "None"
	default:
		res.SLA = slaForPriority(res.Priority)
	}
	return res
}

func slaForPriority(p domain.TriagePriority) string {
	switch p {
	case domain.PriorityP0:
		return "Immediate (Blocker)"
	case domain.PriorityP1:
		return "High Priority"
	case domain.PriorityP2:
		return "Scheduled"
	case domain.PriorityP3:
		return "Low Priority"
	default:
		return "None"
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

// DowngradePriority lowers a triage priority tier by one level when
// mitigating controls are proven. Lowering saturates at P3 and never turns
// an unranked input into DISMISSED.
func DowngradePriority(p domain.TriagePriority) domain.TriagePriority {
	switch p {
	case domain.PriorityP0:
		return domain.PriorityP1
	case domain.PriorityP1:
		return domain.PriorityP2
	case domain.PriorityP2:
		return domain.PriorityP3
	case domain.PriorityP3:
		return domain.PriorityP3
	case domain.PriorityDismissed:
		return domain.PriorityDismissed
	default:
		return p
	}
}

// inboundSurfaces inventories resolved inbound listener surfaces: loopback
// (ScopeLoopback/ScopeUnix, provably local), public (reachable beyond the
// host) and unresolved (no sufficient resolved scope fact).
type inboundSurfaces struct {
	listeners  int
	loopback   int
	public     int
	unresolved int
}

// provenLoopbackOnly reports whether every structural inbound listener is a
// proven loopback/unix bind — the only exposure shape that may lower the
// priority. A single public or unresolved listener among them means no
// isolation, so one loopback surface is never enough.
func (s inboundSurfaces) provenLoopbackOnly() bool {
	return s.listeners > 0 && s.loopback == s.listeners
}

// classifyExposure resolves the exposure factor and the inbound surface
// inventory. Only ScopeLoopback/ScopeUnix listeners count as proven-local:
// ScopeClusterInternal, a trusted-peer/product perimeter or a hypothetical
// profile is not a physical loopback bind. Free-text evidence may
// conservatively mark public exposure but never a proven control — loopback
// prose is not isolation.
func classifyExposure(c *domain.AnalysisCase) (string, inboundSurfaces) {
	var s inboundSurfaces
	if c == nil {
		return "NONE", s
	}
	for _, f := range c.EvidenceGraph.ExposuresList() {
		// Inbound surfaces: resolved listener binds (goanalysis) and
		// deploy-manifest declared inbound surfaces. "dial" is outbound and
		// "auth-middleware" is wiring — not a surface of its own.
		if f.Direction != "inbound" || (f.Kind != "listener" && f.Kind != "deployment") {
			continue
		}
		s.listeners++
		switch f.Scope {
		case domain.ScopeLoopback, domain.ScopeUnix:
			// Only a structural listener bind is a physical loopback/unix
			// surface — a deploy-declared ClusterIP/loopback scope is a
			// hypothetical deployment isolation, not a proven control, so
			// it counts as unresolved, never as isolation evidence.
			if f.Kind == "listener" {
				s.loopback++
			} else {
				s.unresolved++
			}
		case domain.ScopeAllInterfaces, domain.ScopeHostSpecific:
			s.public++
		default:
			if publicLooking(f.Address) {
				s.public++
			} else {
				s.unresolved++
			}
		}
	}
	for _, ev := range c.EvidenceGraph.EvidenceList() {
		if ev.Kind != domain.EvidenceEntrypoint && !strings.Contains(ev.Source, "exposure") && !strings.Contains(ev.Source, "listener") {
			continue
		}
		content := strings.ToLower(ev.Content)
		if strings.Contains(content, "0.0.0.0") || strings.Contains(content, "all-interfaces") {
			s.public++
		}
	}
	switch {
	case s.public > 0:
		return "PUBLIC", s
	case s.provenLoopbackOnly():
		return "INTERNAL", s
	default:
		return "NONE", s
	}
}

// publicLooking reports whether an unclassified listener address is
// conservatively public: a wildcard bind or a decimal-prefixed wildcard
// port. Anything else stays unresolved, never a proven loopback control.
func publicLooking(addr string) bool {
	addr = strings.TrimSpace(addr)
	return strings.Contains(addr, "0.0.0.0") || strings.HasPrefix(addr, ":")
}

// detectAuthentication reports observed inbound authentication wiring. The
// value is informational and never lowers the priority: middleware matched
// by name and position does not prove per-route coverage, and per-handler,
// gateway or deployment auth is outside this scan. An unproven absence is
// UNKNOWN, not NONE as proven absence.
func detectAuthentication(c *domain.AnalysisCase) string {
	if c == nil {
		return "UNKNOWN"
	}
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction == "inbound" && f.Kind == "auth-middleware" {
			return "REQUIRED"
		}
	}
	return "UNKNOWN"
}

// normalizeSeverity canonicalizes severity aliases used across scanners.
func normalizeSeverity(sev string) string {
	sev = strings.ToUpper(strings.TrimSpace(sev))
	switch sev {
	case "BLOCKER":
		return "CRITICAL"
	case "MODERATE":
		return "MEDIUM"
	default:
		return sev
	}
}

// nominalLevel is the baseline contextual level implied by the advisory
// severity (aliases resolved), falling back to the score bucket when the
// severity is not a ranked name.
func nominalLevel(baseSev string, baseScore float64) domain.RiskLevel {
	switch normalizeSeverity(baseSev) {
	case "CRITICAL":
		return domain.RiskLevelCritical
	case "HIGH":
		return domain.RiskLevelHigh
	case "MEDIUM":
		return domain.RiskLevelMedium
	case "LOW":
		return domain.RiskLevelLow
	case "NONE":
		return domain.RiskLevelNone
	default:
		return defaultRiskLevelForScore(baseScore)
	}
}

// priorityRank orders triage priorities by urgency (lower = more urgent);
// ok=false for values outside the triage scale.
func priorityRank(p domain.TriagePriority) (int, bool) {
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

// clampPriority returns candidate unless it is more urgent than base or not
// a triage priority at all.
func clampPriority(candidate, base domain.TriagePriority) domain.TriagePriority {
	cr, okCandidate := priorityRank(candidate)
	br, okBase := priorityRank(base)
	if !okBase || !okCandidate || cr < br {
		return base
	}
	return candidate
}

// severityRank orders risk levels by severity (lower = less severe), with
// BLOCKER and MODERATE resolved to their canonical levels. UNKNOWN is
// unranked — never treated as CRITICAL.
func severityRank(l domain.RiskLevel) (int, bool) {
	switch normalizeSeverity(string(l)) {
	case "NONE":
		return 0, true
	case "LOW":
		return 1, true
	case "MEDIUM":
		return 2, true
	case "HIGH":
		return 3, true
	case "CRITICAL":
		return 4, true
	default:
		return 0, false
	}
}

// clampSeverity returns candidate unless it is more severe than base or not
// a ranked level.
func clampSeverity(candidate, base domain.RiskLevel) domain.RiskLevel {
	cr, okCandidate := severityRank(candidate)
	br, okBase := severityRank(base)
	if !okBase || !okCandidate || cr > br {
		return base
	}
	return candidate
}

// clampScore rounds the candidate to one decimal and caps it at the base
// score.
func clampScore(candidate, base float64) float64 {
	score := math.Round(candidate*10) / 10
	if score > base {
		return base
	}
	return score
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

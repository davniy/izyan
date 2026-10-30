package justification

import (
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/finding"
)

// Build constructs an audit-ready AnalysisJustification from the case's one
// authoritative requested-finding projection.
//
// The dossier identifies the selected witness — the record whose independently
// admitted assessment grounds the answer — and reads that record's own defect
// mechanism. A composed CVE positive therefore explains the gRPC witness, never
// the primary x/net record. A FAILED outcome publishes no verdict, and an
// external dependency keeps INCONCLUSIVE plus the named missing fact.
//
// A case without a requested finding (a legacy single-assessment result or an
// in-flight analysis that has not composed yet) keeps its own recorded verdict
// verbatim: a historical INCONCLUSIVE is never reinterpreted as an external
// dependency.
func Build(c *domain.AnalysisCase) domain.AnalysisJustification {
	if c == nil {
		return domain.AnalysisJustification{}
	}
	requested := c.RequestedFinding
	verdict := domain.VerdictInconclusive
	switch {
	case requested != nil:
		// FAILED carries no verdict, and the empty value is preserved: the
		// dossier must not turn an analysis failure into INCONCLUSIVE.
		verdict = requested.Verdict
	case c.Verdict != nil:
		verdict = c.Verdict.Verdict
	}
	d := domain.AnalysisJustification{
		VulnerabilityID: c.Vulnerability.ID,
		Verdict:         verdict,
	}

	witness := selectWitness(c)
	if witness != nil {
		appendMechanism(&d, witness.CVEAnalysis, verdict)
	}
	if requested == nil {
		return d
	}
	d.VulnerabilityID = requested.RequestedID
	appendWitnessProvenance(&d, requested, witness, c)
	appendCorpusBoundary(&d, requested)
	appendOutcome(&d, requested)
	appendAssessmentAxes(&d, c)
	return d
}

// selectWitness resolves the record the requested answer rests on. A positive
// names its witnesses as proof origins; the first origin is the deciding one.
// Without a positive the primary record is the record that was assessed.
//
// It returns nil when the case names an origin whose assessment is missing:
// the dossier then reports no mechanism rather than borrowing another record's.
func selectWitness(c *domain.AnalysisCase) *domain.AnalysisCase {
	requested := c.RequestedFinding
	if requested == nil || len(requested.ProofOrigins) == 0 {
		return c
	}
	origin := requested.ProofOrigins[0]
	if origin.AssessmentID == c.ID {
		return c
	}
	for _, related := range c.RelatedRecords {
		if related.Analysis != nil && related.ID == origin.AssessmentID {
			return related.Analysis
		}
	}
	return nil
}

// appendMechanism records the witness's own defect mechanism. The auxiliary
// sites stay open questions only while the requested answer is not a negative.
func appendMechanism(d *domain.AnalysisJustification, analysis *domain.CVEAnalysisProposal, verdict domain.Verdict) {
	if analysis == nil || len(analysis.Mechanisms) == 0 {
		return
	}
	m := analysis.Mechanisms[0]
	d.TechnicalMechanism = m.Summary
	if len(m.FaultingSites) > 0 {
		d.TechnicalMechanism = fmt.Sprintf("%s (сайты дефекта: %s)", m.Summary, strings.Join(m.FaultingSites, ", "))
		for _, fs := range m.FaultingSites {
			d.VerifiedFacts = append(d.VerifiedFacts, fmt.Sprintf("Сайт дефекта: %s", fs))
		}
	}
	if verdict == "" || verdict == domain.VerdictNotAffected || verdict == domain.VerdictNoExploitPathFound {
		return
	}
	for _, aux := range m.AuxiliarySites {
		d.HumanRemainder = append(d.HumanRemainder, domain.HumanRemainderItem{
			Obligation: "verify_auxiliary_symbol",
			Question:   fmt.Sprintf("Подтвердить, что функция %s является вспомогательным транспортом/проверкой и не содержит сайта сбоя", aux),
		})
	}
}

// appendWitnessProvenance states which independent assessment produced the
// answer, from which record bytes, under which attribution and profile. A
// consumer can therefore see that a composed CVE answer is not the primary
// record's.
func appendWitnessProvenance(d *domain.AnalysisJustification, requested *domain.RequestedFinding, witness, primary *domain.AnalysisCase) {
	for _, origin := range requested.ProofOrigins {
		var parts []string
		if origin.AssessmentID != "" {
			parts = append(parts, "оценка "+string(origin.AssessmentID))
		}
		if origin.Record.RecordID != "" {
			parts = append(parts, "запись "+origin.Record.RecordID)
		}
		if origin.Record.DocumentDigest != "" {
			parts = append(parts, origin.Record.DocumentDigest)
		}
		if origin.AttributionID != "" {
			parts = append(parts, "атрибуция "+origin.AttributionID)
		}
		if origin.MechanismID != "" {
			parts = append(parts, "механизм "+origin.MechanismID)
		}
		if origin.Profile != "" {
			parts = append(parts, "профиль "+string(origin.Profile))
		}
		d.VerifiedFacts = append(d.VerifiedFacts, "Свидетель запрошенного ответа: "+strings.Join(parts, "; "))
	}
	if witness == nil || primary == nil || witness.ID == primary.ID {
		return
	}
	module := witness.Vulnerability.Module
	if module == "" && len(witness.Vulnerability.AffectedPackages) > 0 {
		module = witness.Vulnerability.AffectedPackages[0].Path
	}
	if module == "" {
		module = "не указан"
	}
	d.VerifiedFacts = append(d.VerifiedFacts, fmt.Sprintf(
		"Запрос %s отвечен независимой оценкой %s (модуль %s; первичная запись %s не переиспользована)",
		requested.RequestedID, witness.Vulnerability.ID, module, primary.Vulnerability.ID))
}

// appendCorpusBoundary carries Addendum A's verbatim boundary statement so a
// CVE-wide negative can never be read without its corpus limits.
func appendCorpusBoundary(d *domain.AnalysisJustification, requested *domain.RequestedFinding) {
	if requested.CorpusNegativeBasis == nil {
		return
	}
	d.VerifiedFacts = append(d.VerifiedFacts, requested.CorpusNegativeBasis.BoundaryStatement)
}

// appendOutcome records a FAILED or EXTERNAL_DEPENDENCY terminal. A failure
// contributes work items (not verified facts), and an external dependency names
// the decision-changing fact rather than an unspecified "uncertainty".
func appendOutcome(d *domain.AnalysisJustification, requested *domain.RequestedFinding) {
	switch requested.Outcome {
	case domain.OutcomeFailed:
		codes := failureCodes(requested.Gaps)
		summary := "Итог запроса: FAILED (вердикт отсутствует)"
		if len(codes) > 0 {
			summary += "; коды отказов: " + strings.Join(codes, ", ")
		}
		d.VerifiedFacts = append(d.VerifiedFacts, summary)
		for _, gap := range requested.Gaps {
			d.HumanRemainder = append(d.HumanRemainder, domain.HumanRemainderItem{
				Obligation: string(gap.Obligation),
				Question:   fmt.Sprintf("Анализ не завершён (%s/%s): %s", gap.Owner, gap.Code, gap.Message),
			})
		}
	case domain.OutcomeExternal:
		d.VerifiedFacts = append(d.VerifiedFacts, "Итог запроса: EXTERNAL_DEPENDENCY (INCONCLUSIVE)")
		for _, dep := range requested.ExternalDependencies {
			d.HumanRemainder = append(d.HumanRemainder, domain.HumanRemainderItem{
				Obligation: string(dep.AffectedObligation),
				Question: fmt.Sprintf("Внешний факт, меняющий ответ: %s. Чем разрешается: %s",
					dep.MissingFact, dep.ResolvingEvidence),
			})
		}
	}
}

// appendAssessmentAxes records the same derived pair the report surfaces. It
// reuses the publication gate rather than re-deriving a second answer: a case
// whose saved conclusion does not re-admit contributes no display axes. The
// values are presentation only and never replace the verdict above.
func appendAssessmentAxes(d *domain.AnalysisJustification, c *domain.AnalysisCase) {
	view, err := finding.Project(c)
	if err != nil {
		return
	}
	row, ok := view.Axes.TargetRequested()
	if !ok {
		return
	}
	d.VerifiedFacts = append(d.VerifiedFacts, "Оси оценки запроса: "+axisSentence(row))
	for _, record := range view.Axes.Records {
		if record.AssessmentID == row.AssessmentID && record.Profile == row.Profile {
			continue
		}
		d.VerifiedFacts = append(d.VerifiedFacts, fmt.Sprintf(
			"Оси оценки записи %s (оценка %s, профиль %s): %s",
			record.SubjectID, record.AssessmentID, record.Profile, axisSentence(record)))
	}
}

// axisSentence renders one projected row in the dossier's Russian prose. A
// scoped positive names its boundary: it never reads as deployment-wide
// exploitability.
func axisSentence(row finding.AxisRow) string {
	vulnerability := "неизвестно"
	switch row.VulnerableCodeInBuild {
	case finding.AxisTrue:
		vulnerability = "да"
	case finding.AxisFalse:
		vulnerability = "нет"
	}
	exploitability := "неизвестно"
	switch row.Exploitable {
	case finding.AxisTrue:
		if row.ExploitabilityScope == "" {
			exploitability = "да"
			break
		}
		exploitability = "да, на границе " + axisScopeLabel(row.ExploitabilityScope) +
			"; доступ атакующего в развёртывании не установлен"
	case finding.AxisFalse:
		exploitability = "нет (в записанных сборке, профиле и допущениях)"
	case finding.AxisNotApplicable:
		exploitability = "неприменимо"
	}
	return "уязвимый код/версия в оцениваемой сборке: " + vulnerability +
		"; эксплуатируемость: " + exploitability
}

func axisScopeLabel(scope domain.ExploitabilityScope) string {
	switch scope {
	case domain.ScopeLibraryAPI:
		return "library API"
	case domain.ScopeTransportPeer:
		return "transport-peer"
	default:
		return string(scope)
	}
}

// failureCodes renders typed gap causes as OWNER/CODE, deduplicated and in
// producer order.
func failureCodes(gaps []domain.AnalysisGap) []string {
	var out []string
	seen := map[string]bool{}
	for _, gap := range gaps {
		code := string(gap.Owner) + "/" + string(gap.Code)
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}

package justification

import (
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/cveanalysis"
	"github.com/fedorovmv/izyan/internal/domain"
)

// Build constructs an audit-ready AnalysisJustification based strictly on
// verified facts and proposals, preserving honest uncertainty (human
// remainder). LLM-proposed sites are never copied into VerifiedFacts —
// only deterministic check results (TRUE proposal verifications)
// qualify as verified.
func Build(c *domain.AnalysisCase) domain.AnalysisJustification {
	verdict := domain.VerdictInconclusive
	if c.Verdict != nil {
		verdict = c.Verdict.Verdict
	}

	d := domain.AnalysisJustification{
		VulnerabilityID: c.Vulnerability.ID,
		Verdict:         verdict,
	}

	// Verified facts come only from persisted deterministic check results
	// — never from LLM site strings.
	for _, rec := range c.ProposalVerifications {
		if rec.Result != domain.ClaimTrue {
			continue
		}
		subject := rec.SiteText
		if rec.Subject != nil {
			subject = rec.Subject.Package + " " + rec.Subject.Symbol
		}
		d.VerifiedFacts = append(d.VerifiedFacts,
			fmt.Sprintf("%s: %s — %s", rec.Check, subject, rec.Detail))
	}

	if c.CVEAnalysis != nil && len(c.CVEAnalysis.Mechanisms) > 0 {
		pkgs := cveanalysis.AffectedPackagePaths(c.Vulnerability)
		ref := domain.ProposalRef{Source: domain.ProposalSourceCVEResearch, ID: c.CVEAnalysis.ID, Revision: c.CVEAnalysis.Revision}

		var summaries []string
		for i, m := range c.CVEAnalysis.Mechanisms {
			summary := m.Summary
			if len(m.FaultingSites) > 0 {
				summary = fmt.Sprintf("%s (предполагаемые сайты дефекта: %s)", m.Summary, strings.Join(m.FaultingSites, ", "))
			}
			summaries = append(summaries, summary)

			// Auxiliary classifications unresolved by deterministic checks
			// become explicit obligations whenever the verdict depends on
			// where the defect sits — including negative ones. Only a
			// proven NOT_AFFECTED (the defect code is absent altogether)
			// makes the role question moot.
			if verdict == domain.VerdictNotAffected {
				continue
			}
			mref := ref
			mref.MechanismID = m.ID
			if mref.MechanismID == "" {
				mref.MechanismID = fmt.Sprintf("M-%d", i+1)
			}
			for _, aux := range m.AuxiliarySites {
				item := domain.HumanRemainderItem{
					Obligation: "verify_auxiliary_symbol",
					Proposal:   &mref,
				}
				if subj, ok := cveanalysis.NormalizeSite(aux, pkgs); ok {
					s := subj
					item.Subject = &s
					item.Question = fmt.Sprintf(
						"LLM отнесла `%s.%s` к вспомогательным функциям. По исходникам уязвимой версии и патчу определите роль функции: выполняет ли она дефектную операцию или только передаёт данные? До проверки исключать её из набора потенциально дефектных функций нельзя.",
						subj.Package, subj.Symbol)
				} else {
					item.Question = fmt.Sprintf(
						"LLM отнесла `%s` к вспомогательным функциям, но ссылку нельзя однозначно связать с пакетом и символом. Уточните, какая функция имелась в виду, и проверьте её роль по исходникам.",
						aux)
				}
				d.HumanRemainder = append(d.HumanRemainder, item)
			}
		}
		d.TechnicalMechanism = strings.Join(summaries, " ")
	}

	return d
}

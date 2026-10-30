package evaluator

import (
	"fmt"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fixbinding"
)

// absenceFalsifier reports whether a FALSE claim rests on a subject's absence
// from the product's build graph or from the selected dependency source. Those
// are the negatives the version-binding rule governs: absence is evidence about
// real subjects only.
func absenceFalsifier(falsifier string) bool {
	switch falsifier {
	case domain.FalsifierPackageAbsent,
		domain.FalsifierLocusPackageAbsent,
		domain.FalsifierMissingSourceSymbol:
		return true
	}
	return false
}

// admitAbsenceIdentity re-admits the identity behind persisted absence
// evidence. It runs at the shared deterministic verdict boundary — not only in
// the producer — so a saved negative cannot survive replay merely because it
// was saved.
//
// Three things are refused, from one admission answer:
//
//   - a subject in the model's absent set whose candidate names no established
//     subject of the selected version is pruned, so the grouped all-absent
//     coverage rules (allUnresolvedAbsent, locusCoversUnresolved) can no longer
//     treat it as proven absence;
//   - a persisted FALSE claim whose absence falsifier binds such a subject is
//     demoted to UNKNOWN with a typed refusal, so it can neither ground nor
//     block a verdict it did not earn;
//   - an absence falsifier whose evaluated subject set is empty is demoted the
//     same way: a negative that names no subject is a vacuous closure, not
//     proof about any subject, and pruning must not be able to empty a claim
//     into an admission.
//
// A stored content-derived fix binding is withdrawn evidence: the refusal names
// it rather than letting the payload decay into a weaker route. The evidence
// the record carries is untouched: only the conclusion is refused.
func admitAbsenceIdentity(in VerdictInput, out *VerdictInput,
	conds map[domain.ConditionID]domain.Condition) []verdictRefusal {

	var refusals []verdictRefusal

	if in.RootCause != nil && in.RootCause.FixBinding != nil {
		refusals = append(refusals, verdictRefusal{
			kind:    refusalCandidateIdentity,
			message: in.RootCause.FixBinding.Notice(),
		})
	}

	// One admission for the whole verdict input. Fresh analysis and replay both
	// reach it from persisted data — the candidate records, the exact record,
	// the affected chain, the captured bytes and the admitted build graph — so
	// they cannot disagree about a subject or a cover.
	proof := fixbinding.AdmitModelProof(fixbinding.AdmissionInput{
		Product:        in.Product,
		Vulnerability:  in.Vulnerability,
		RecordPin:      in.RecordPin,
		AdvisoryRecord: in.AdvisoryRecord,
		Affected:       &in.Affected,
		Evidence:       in.Evidence,
	}, in.RootCause)
	absenceAdmission := domain.AdmitAbsenceFor(in.RootCause, in.Vulnerability, &in.Affected,
		in.RecordPin, in.Model.AbsentSubjects,
		affected.AdmittedBuildGraph(in.Product, in.Evidence), proof)

	if len(out.Model.AbsentSubjects) > 0 {
		kept := make([]domain.SymbolRef, 0, len(out.Model.AbsentSubjects))
		for _, s := range out.Model.AbsentSubjects {
			if admission := absenceAdmission.Admits(s); !admission.Admitted {
				refusals = append(refusals, verdictRefusal{
					kind:    refusalCandidateIdentity,
					message: fmt.Sprintf("absent subject %s refused: %s", subjectName(s), admission.Reason),
				})
				continue
			}
			kept = append(kept, s)
		}
		out.Model.AbsentSubjects = kept
	}

	for i := range out.Claims {
		claim := &out.Claims[i]
		if claim.Result != domain.ClaimFalse || !absenceFalsifier(claim.Falsifier) {
			continue
		}
		cond, ok := conds[claim.ConditionID]
		if !ok {
			continue
		}
		// A config-flag absence measures whether a configuration package is
		// linked into the build. It names no defect subject, so the
		// defect-identity and cover rules do not apply; the measurement gate
		// still requires the package and the inventory the negative cites.
		if _, typedConfig := domain.ConfigFlagSubject(cond); typedConfig {
			continue
		}
		// The claim must name its exact subject set and, when a content proof
		// established one, equal the admitted necessary cover: there is no
		// fallback to whatever remains in Model.RootCauses, and an absent
		// subset never stands while another alternative is linked or
		// unresolved.
		if err := absenceAdmission.CheckClaim(cond, *claim); err != nil {
			claim.Result = domain.ClaimUnknown
			refusals = append(refusals, verdictRefusal{
				kind:        refusalCandidateIdentity,
				conditionID: claim.ConditionID,
				message: fmt.Sprintf(
					"negative for %s refused: %s", claim.ConditionID, err),
			})
		}
	}
	return refusals
}

// subjectName renders a subject for refusal text.
func subjectName(s domain.SymbolRef) string {
	if s.Symbol == "" {
		return s.Package
	}
	return s.Package + "." + s.Symbol
}

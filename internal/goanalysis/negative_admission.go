package goanalysis

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/davniy/izyan/internal/domain"
)

type NegativeAdmissionInput struct {
	Product domain.ProductSnapshot
	Vulnerability domain.Vulnerability
	RecordPin *domain.RecordPin
	AdvisoryRecord *domain.AdvisoryRecordCapture
	Model *domain.ExploitModel
	Evidence []domain.Evidence
}

// ValidateVerifiedNegative admits persisted verification without loading source.
// Candidate measurement prerequisites remain domain.ValidateNegativeEvidence;
// a verified locus negative additionally needs its cited complete kernel result.
func ValidateVerifiedNegative(in NegativeAdmissionInput, claim domain.Claim, cond domain.Condition) error {
	product, model, evidence := in.Product, in.Model, in.Evidence
	if claim.Falsifier == domain.FalsifierZeroValueConfig || claim.Falsifier == domain.FalsifierSafeConfigKey {
		return configScope("unsupported configuration falsifier has no independent proof")
	}
	if err := domain.ValidateNegativeEvidence(product, claim, cond, evidence); err != nil {
		return err
	}
	nv := claim.NegativeVerification
	if nv == nil {
		return errors.New("no negative verification record")
	}
	if nv.Status != domain.NegativeVerified {
		return fmt.Errorf("negative verification status is %q, not %q", nv.Status, domain.NegativeVerified)
	}
	if !domain.NegativeRequiresTarget(claim, cond) {
		return nil
	}
	if nv.BuildContext == nil {
		return errors.New("verified negative has no build context: it cannot describe the analyzed product build")
	}
	build := domain.EffectiveBuildContext(product)
	if err := nv.BuildContext.Matches(build); err != nil {
		return fmt.Errorf("verified negative: %w", err)
	}
	if claim.Falsifier == domain.FalsifierSafeConfigAssignment {
		_, err := ValidateConfigCertificateEvidence(in, claim, cond)
		return err
	}
	if claim.Falsifier != domain.FalsifierLocusFunctionUnreached {
		return nil
	}
	subjects, err := exactLocusConditionSubjects(cond)
	if err != nil {
		return err
	}
	if _, err := domain.ValidateDeadnessPremise(model, subjects, evidence); err != nil {
		return fmt.Errorf("verified locus deadness premise: %w", err)
	}
	cited := make(map[domain.EvidenceID]bool, len(nv.EvidenceIDs))
	for _, id := range nv.EvidenceIDs {
		cited[id] = true
	}
	problem := "no cited full bounded kernel payload"
	for _, e := range evidence {
		if !cited[e.ID] || e.Kind != domain.EvidenceSourceSnippet {
			continue
		}
		if e.BuildContext == nil {
			problem = "kernel evidence has no build context"
			continue
		}
		if err := e.BuildContext.Matches(build); err != nil {
			problem = "kernel evidence: " + err.Error()
			continue
		}
		var result UnreachabilityResult
		if err := json.Unmarshal([]byte(e.Content), &result); err != nil {
			problem = "kernel evidence does not decode: " + err.Error()
			continue
		}
		if err := result.ValidateComplete(build); err != nil {
			problem = err.Error()
			continue
		}
		if len(result.Subjects) != len(subjects) {
			problem = "kernel subjects do not exactly cover the condition"
			continue
		}
		matches := true
		for _, got := range result.Subjects {
			found := false
			for _, want := range subjects {
				if got.Package == want.Package && got.Symbol == want.Symbol {
					found = true
					break
				}
			}
			if !found {
				matches = false
				break
			}
		}
		if matches {
			return nil
		}
		problem = "kernel subjects differ from the exact condition subjects"
	}
	return fmt.Errorf("verified locus negative refused: %s", problem)
}

// exactLocusConditionSubjects rejects malformed explicit identities, rather than
// dropping them or deriving fallback coverage from the model or a payload.
func exactLocusConditionSubjects(cond domain.Condition) ([]domain.SymbolRef, error) {
	refs := append([]domain.SymbolRef(nil), cond.Subjects...)
	if cond.Subject != nil {
		refs = append(refs, *cond.Subject)
	}
	seen := make(map[domain.SymbolRef]bool, len(refs))
	out := make([]domain.SymbolRef, 0, len(refs))
	for _, ref := range refs {
		if ref.Package == "" || ref.Symbol == "" {
			return nil, errors.New("verified locus requires exact package/symbol condition subjects")
		}
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("verified locus requires explicit nonempty condition subjects")
	}
	return out, nil
}

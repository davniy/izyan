package evaluator

import (
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
)

// evalLocus evaluates a C-LOCUS condition — execution of the defect locus
// (spec §8).
//
// Source observations and exploit semantics are separated:
//
//   - The source layer reports whether a named function/package can execute.
//     A missing-call observation says the pipeline runs and the check is
//     absent; it never says the check's body ran.
//   - The admitted defect-semantics contract decides which execution is the
//     defect locus: the contracted check for DEFECTIVE_CHECK (its invocation
//     is necessary), the contracted omission-site pipeline for OMITTED_CHECK
//     (the absent check is not the execution locus), and nothing for
//     UNRESOLVED.
//
// TRUE does not follow any EV-MISSING-CALL prefix. For an omission contract it
// follows the typed omission witness bound to the contract — the omission site
// executes while the check is absent — or a genuine call path to the anchored
// pipeline. For a defective-check contract it follows a call path to the check.
//
// FALSE is a candidate only on a measured basis and only under admitted
// semantics:
//   - locus-package-absent needs a completed, complete package inventory
//     matching the case build context;
//   - locus-function-unreached needs a completed, complete, non-opaque
//     source measurement covering the semantic locus subject by subject.
//
// A model that carries semantic claims without an admitted contract, an
// UNRESOLVED contract or an unadmitted legacy omission model yields UNKNOWN.
func evalLocus(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evalLocusRaw(cond, c))
}

func evalLocusRaw(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.SymbolReachable(locus)",
	}
	// Exact declared locus set. Under a contract it is advisory provenance
	// and the expert non-locus proposal basis, not the execution locus.
	declared := append([]domain.SymbolRef(nil), cond.Subjects...)
	if len(declared) == 0 && cond.Subject != nil {
		declared = append(declared, *cond.Subject)
	}
	if len(declared) == 0 {
		claim.Limitations = append(claim.Limitations,
			"пустой список уязвимых функций; необходимость не установлена")
		return claim
	}

	// Resolve the semantic execution locus from the admitted contract.
	locus := declared
	omissionSite := false
	if c.Exploit != nil && c.Exploit.DefectSemantics != nil {
		if err := domain.ValidateDefectSemanticsModel(*c.Exploit, c.EvidenceGraph.EvidenceList()); err != nil {
			claim.Limitations = append(claim.Limitations,
				"семантика дефекта не допущена ("+err.Error()+"); локус дефекта остаётся UNKNOWN")
			return claim
		}
		contract := c.Exploit.DefectSemantics
		switch contract.Mode {
		case domain.DefectSemanticsDefectiveCheck:
			locus = []domain.SymbolRef{contract.Check}
		case domain.DefectSemanticsOmittedCheck:
			if contract.Pipeline == nil {
				claim.Limitations = append(claim.Limitations,
					"контракт OMITTED_CHECK не привязывает конвейер; локус дефекта остаётся UNKNOWN")
				return claim
			}
			locus = []domain.SymbolRef{*contract.Pipeline}
			omissionSite = true
		default:
			claim.Limitations = append(claim.Limitations,
				fmt.Sprintf("режим семантики дефекта %q не допускает локус-решение", contract.Mode))
			return claim
		}
	} else if c.Exploit != nil && domain.ModelCarriesSemanticClaims(c.Exploit) {
		claim.Limitations = append(claim.Limitations,
			"модель несёт семантические условия без допущенного контракта семантики дефекта; локус дефекта остаётся UNKNOWN")
		return claim
	}

	// Proposed falsifier note stays advisory and uses the declared set: the
	// expert's non-locus decisions concern advisory symbols, not the
	// semantic execution locus.
	proposed := proposedLocusNote(c, declared)

	// Omission site: the typed witness proves the anchored pipeline runs
	// while the contracted check is absent. This is execution of the omission
	// site, never execution of the absent check's body.
	if omissionSite && c.Exploit != nil {
		if match, reasons := domain.MatchOmissionWitness(c.Exploit.DefectSemantics, cond,
			c.EvidenceGraph.EvidenceList(), c.Product, domain.MissingCallOmitted); match != nil {
			claim.Result = domain.ClaimTrue
			claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, match.EvidenceID)
			claim.Explanation = "площадка пропуска исполняется: конвейер " + match.Witness.Pipeline.Symbol +
				" достигается из продуктового кода, а проверяемая проверка отсутствует на этом пути"
			if proposed != "" {
				claim.Limitations = append(claim.Limitations, proposed)
			}
			return claim
		} else {
			claim.Limitations = append(claim.Limitations, reasons...)
		}
	}

	// Call paths are published only by completed govulncheck runs, so a
	// path that reaches the semantic locus subject is a TRUE.
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			for _, sym := range locus {
				if !frameMatches(fr, sym) {
					continue
				}
				if cp.EvidenceID != "" {
					claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, cp.EvidenceID)
				}
				claim.Result = domain.ClaimTrue
				claim.Explanation = fmt.Sprintf(
					"трасса вызовов govulncheck достигает функции дефектного локуса %s.%s",
					sym.Package, sym.Symbol)
				if proposed != "" {
					claim.Limitations = append(claim.Limitations, proposed)
				}
				return claim
			}
		}
	}
	for _, subj := range locus {
		want := subj.Package + "." + subj.Symbol
		chain, ok := c.EvidenceGraph.ModuleReachable[want]
		if !ok {
			continue
		}
		claim.Result = domain.ClaimTrue
		claim.EvidenceIDs = append(moduleReachEvidence(c), moduleUsageEvidence(c)...)
		claim.Explanation = fmt.Sprintf(
			"функция дефектного локуса %s достижима через вызовы внутри модуля: %s",
			want, strings.Join(chain, " -> "))
		if proposed != "" {
			claim.Limitations = append(claim.Limitations, proposed)
		}
		return claim
	}

	// Negative basis over the semantic locus. The premise that this deadness
	// falsifies the vulnerability is carried by the admitted contract
	// resolution above: a missing contract already returned UNKNOWN.
	if c.Exploit != nil {
		premise, err := domain.ValidateDeadnessPremise(c.Exploit, locus, c.EvidenceGraph.EvidenceList())
		if err != nil {
			claim.Limitations = append(claim.Limitations,
				"недостижимость локуса не допущена как негатив: "+err.Error())
			if proposed != "" {
				claim.Limitations = append(claim.Limitations, proposed)
			}
			return claim
		}
		if premise.Basis != "" {
			claim.Limitations = append(claim.Limitations, "семантическое основание: "+premise.Basis)
		}
	}

	set, ids, err := packageImportSet(c)
	if err != nil {
		claim.Limitations = append(claim.Limitations, err.Error())
		return claim
	}
	var present []string
	for _, s := range locus {
		if set[s.Package] {
			present = appendUnique(present, s.Package)
		}
	}
	if len(present) == 0 {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierLocusPackageAbsent
		claim.EvidenceIDs = ids
		claim.Explanation = fmt.Sprintf(
			"все пакеты дефектного локуса (%d) отсутствуют в графе сборки (go list -deps); уязвимый код не скомпилирован в приложение и не может выполниться",
			len(locus))
		claim.Limitations = append(claim.Limitations,
			"FALSE (предварительно): отсутствие пакета проверено для текущего контекста сборки (GOOS/GOARCH/теги)")
		if proposed != "" {
			claim.Limitations = append(claim.Limitations, proposed)
		}
		return claim
	}

	// A linked package with no trace is not yet a measurement: the
	// source-level unreachability scan must have completed over a complete,
	// non-opaque census and cover the semantic locus subject.
	locusCond := cond
	locusCond.Subjects = append([]domain.SymbolRef(nil), locus...)
	unreachedClaim := domain.Claim{
		Result:    domain.ClaimFalse,
		Falsifier: domain.FalsifierLocusFunctionUnreached,
	}
	if err := domain.ValidateNegativeEvidence(c.Product, unreachedClaim, locusCond,
		c.EvidenceGraph.EvidenceList()); err != nil {
		claim.Limitations = append(claim.Limitations,
			"пакеты дефектного локуса входят в сборку, но измерение недостижимости не допущено: "+
				err.Error()+"; недостижимость функций остаётся UNKNOWN")
		if proposed != "" {
			claim.Limitations = append(claim.Limitations, proposed)
		}
		return claim
	}
	claim.Result = domain.ClaimFalse
	claim.Falsifier = domain.FalsifierLocusFunctionUnreached
	claim.EvidenceIDs = ids
	claim.Explanation = fmt.Sprintf(
		"пакеты дефектного локуса входят в сборку, но функции локуса (%d) не имеют обнаруженных трасс вызовов; требуется верификация недостижимости",
		len(locus))
	claim.Limitations = append(claim.Limitations,
		"FALSE (предварительно): недостижимость функции в скомпилированном пакете требует негативной верификации")
	if proposed != "" {
		claim.Limitations = append(claim.Limitations, proposed)
	}
	return claim
}

// packageImportSet decodes the persisted `go list -deps -json` package-list
// evidence into the set of linked import paths. Only a completed, complete
// inventory whose recorded build context matches the case's effective context
// can serve as an absence measurement; a partial, untyped or mismatched
// record is a loading gap, never absence.
func packageImportSet(c *domain.AnalysisCase) (map[string]bool, []domain.EvidenceID, error) {
	e, err := domain.SelectCompletePackageList(c.Product, c.EvidenceGraph.EvidenceList())
	if err != nil {
		return nil, nil, fmt.Errorf(
			"нет допущенного списка пакетов (go list -deps) для текущего контекста сборки: %w; отсутствие в графе сборки не проверено", err)
	}
	set, derr := affected.PackageImportPaths([]byte(e.Content))
	if derr != nil {
		return nil, nil, fmt.Errorf(
			"не удалось прочитать список пакетов %s: %w; отсутствие в графе сборки не проверено", e.ID, derr)
	}
	return set, []domain.EvidenceID{e.ID}, nil
}

// proposedLocusNote answers the expert's review question without code
// reading: if every machine non-locus proposal were approved and recorded
// as expert basis, would the reduced declared locus set be fully absent from
// the persisted build graph? Returns a human-readable note or "" when no
// proposal set exists or the reduced set still has linked packages.
// The machine verifies the package-absence half; the necessity half stays
// the expert's recorded decision.
func proposedLocusNote(c *domain.AnalysisCase, symbols []domain.SymbolRef) string {
	if c.Exploit == nil || len(c.Exploit.ProposedNonLocus) == 0 {
		return ""
	}
	proposed := map[domain.SymbolRef]bool{}
	for _, d := range c.Exploit.ProposedNonLocus {
		proposed[d.Symbol] = true
	}
	var remaining []domain.SymbolRef
	var pkgs []string
	for _, s := range symbols {
		if !proposed[s] {
			remaining = append(remaining, s)
			pkgs = append(pkgs, s.Package)
		}
	}
	if len(remaining) == 0 || len(remaining) == len(symbols) {
		return ""
	}
	set, _, err := packageImportSet(c)
	if err != nil {
		return ""
	}
	for _, s := range remaining {
		if set[s.Package] {
			return ""
		}
	}
	return fmt.Sprintf(
		"предварительный вывод ждёт подтверждения эксперта: если утвердить %d предложенных решений `non_locus`, все остальные пакеты с уязвимым кодом (%s) отсутствуют в сборке (`go list -deps`) → следует NO_EXPLOIT_PATH_FOUND",
		len(symbols)-len(remaining), strings.Join(pkgs, ", "))
}

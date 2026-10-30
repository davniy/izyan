// Package rootcause automates RootCauseModel construction without an LLM:
// candidates come from authoritative sources (advisory symbols, the record's
// own vulnerable-operation declarations, the fix artifacts the record declares)
// and are verified against the actual source tree before being trusted.
package rootcause

import (
	"context"
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fix"
	"github.com/davniy/izyan/internal/fixbinding"
	"github.com/davniy/izyan/internal/goanalysis"
)

// Resolver produces root-cause candidates from advisory data and the captured
// fix artifacts, following the spec priority: affected symbols first, then the
// fix material the record declares.
type Resolver struct {
	Fix fix.Resolver
	// Patch is the configured fix-artifact source. nil disables patch-based
	// candidates and is recorded as an input gap rather than as missing
	// artifacts.
	Patch  fix.ArtifactProvider
	Source *goanalysis.Index
 Captures *SourceCaptureSet
 GoTool affected.GoTool
}

func (r Resolver) Resolve(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	model := &domain.RootCauseModel{Status: domain.RootCauseNotFound}
	var evs []domain.Evidence

	// Priority 1: affected symbols named by the advisory.
	for _, s := range v.AffectedSymbols {
		model.RootCauses = append(model.RootCauses, domain.RootCause{
			Package:   s.Package,
			Symbol:    s.Symbol,
			Role:      domain.RootCauseSink,
			Mechanism: "advisory-listed affected symbol",
			Origin:    domain.RootCauseOriginAdvisory,
		})
	}
	if len(model.RootCauses) > 0 {
		evs = append(evs, domain.Evidence{
			Kind:    domain.EvidenceAdvisory,
			Quality: domain.QualityAuthoritative,
			Source:  "advisory affected symbols",
			Tool:    "vulnerability.OSV",
			Content: symbolList(v.AffectedSymbols),
		})
	}

	// Priority 2: the vulnerable operation the record's own prose names, when
	// exactly one declaration source-binds inside the record's own affected
	// scope. A declaration that does not bind uniquely admits nothing; it is
	// preserved on the model so the fallback cannot silently drop it.
	if len(model.RootCauses) == 0 {
		declEvs, declLims := r.resolveDeclarations(ctx, c, v, model)
		evs = append(evs, declEvs...)
		model.Limitations = append(model.Limitations, declLims...)
		for _, b := range model.OperationBindings {
			model.RootCauses = append(model.RootCauses, domain.RootCause{
				Package:   b.Package,
				Symbol:    b.Symbol,
				Role:      domain.RootCauseSink,
				Mechanism: "advisory prose operation (" + b.AffectedEntry + ")",
				Origin:    domain.RootCauseOriginAdvisory,
			})
		}
	}

	// Priority 3: functions changed by the fix material the record declares.
	// With a priority-1/2 subject resolved these stay corroborating
	// alternatives — a patch-changed internal function never displaces an
	// independently bound operation.
	//
	// Every distinct locator is requested and every relevant captured artifact
	// is inventoried. Stopping at the first successful patch both hid the
	// record's other references and labelled the ones it never asked for as
	// missing; the accounting now states only what the provider established.
	if refs := r.Fix.Resolve(v); len(refs) > 0 {
		if r.Patch == nil {
			model.Limitations = append(model.Limitations, "patch provider not configured; fix diff not analyzed")
			model.AnalysisGaps = append(model.AnalysisGaps, rootCauseAnalysisGap(domain.GapOwnerInput,
				domain.GapInputResolutionFailed, domain.ObligationRootCause,
				"patch provider not configured; fix diff not analyzed"))
		} else {
			evs = append(evs, r.resolveFixArtifacts(ctx, c, v, refs, model)...)
			// A fix-derived candidate becomes the root cause only when nothing
			// independent named one. The decision is taken once the whole
			// artifact set is inventoried, never per artifact, so a patch that
			// yielded nothing cannot hide the one that did.
			if len(model.Alternatives) > 0 && len(model.RootCauses) == 0 {
				model.RootCauses = model.Alternatives
				model.Alternatives = nil
			}
			// The captured inputs a content proof needs are now all on the
			// model. Derive it here, while the bytes are still in hand: the
			// checker re-derives every premise, and a premise this analysis
			// never captured stays a typed obligation instead of an asserted
			// summary.
			r.proveContentBinding(ctx, c, v, model)
		}
	}

	if len(model.RootCauses) == 0 {
		model.AnalysisGaps = append(model.AnalysisGaps, rootCauseAnalysisGap(domain.GapOwnerCode,
			domain.GapRootCauseUnresolved, domain.ObligationRootCause,
			deterministicRootCauseCause(v, model)))
		return model, evs, nil
	}
	model.Status = domain.RootCauseResolved
	return model, evs, nil
}

// deterministicRootCauseCause states why deterministic root-cause discovery
// found nothing, from structured record facts rather than free text.
func deterministicRootCauseCause(v domain.Vulnerability, model *domain.RootCauseModel) string {
	if len(model.OperationDeclarations) > 0 {
		var parts []string
		for _, d := range model.OperationDeclarations {
			parts = append(parts, fmt.Sprintf("%s (%s)", d.Operation, d.Resolution))
		}
		return "the record's own prose declares vulnerable operation(s) " + strings.Join(parts, ", ") +
			" but no declaration source-bound uniquely inside the record's affected scope"
	}
	switch {
	case len(v.AffectedSymbols) == 0 && len(model.Alternatives) == 0:
		return "deterministic root-cause discovery found neither an advisory-declared affected symbol nor a fix-diff candidate"
	case len(v.AffectedSymbols) == 0:
		return "deterministic root-cause discovery found no advisory-declared affected symbol; fix-diff candidates did not resolve to a source locus"
	default:
		return "advisory-declared affected symbols did not resolve to a deterministic root cause"
	}
}

func rootCauseAnalysisGap(owner domain.GapOwner, code domain.GapCode, obligation domain.Obligation,
	message string) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:      owner,
		Code:       code,
		Obligation: obligation,
		Message:    message,
	}
}

func symbolList(syms []domain.SymbolRef) string {
	parts := make([]string, 0, len(syms))
	for _, s := range syms {
		parts = append(parts, s.Package+"."+s.Symbol)
	}
	return strings.Join(parts, "\n")
}

// packageGuess maps a repo-relative path to the affected package path when
// possible (suffix match on the module path tail).
func packageGuess(v domain.Vulnerability, filePath string) string {
	// fall back: module root file
	if !strings.Contains(filePath, "/") {
		return v.Module
	}
	dir := filePath[:strings.LastIndexByte(filePath, '/')]
	for _, p := range v.AffectedPackages {
		if strings.HasSuffix(dir, strings.TrimPrefix(p.Path, v.Module+"/")) ||
			strings.HasSuffix(p.Path, dir) || p.Path == dir {
			return p.Path
		}
	}
	return v.Module + "/" + dir
}

func isTestFile(p string) bool { return strings.HasSuffix(p, "_test.go") }

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...[truncated]"
}

// Verifier checks candidates against the analyzed source: the symbol must
// exist in the module cache / replaced dependency / vendored tree and belong
// to an affected package. Unverified candidates are dropped into
// Alternatives. A loader failure is never treated as symbol absence: the
// vendored tree answers when it can, and otherwise the candidate stays
// unverified with the loader error named as the limitation.
type Verifier struct {
	Source *goanalysis.Index
}

func (vf Verifier) Verify(ctx context.Context, c *domain.AnalysisCase, m *domain.RootCauseModel, v domain.Vulnerability) []string {
	var limitations []string
	if vf.Source == nil {
		message := "root-cause verifier has no source index; candidates unverified"
		m.AnalysisGaps = append(m.AnalysisGaps, rootCauseAnalysisGap(domain.GapOwnerProof,
			domain.GapProofArtifactMissing, domain.ObligationRootCause, message))
		return []string{message}
	}
	// The persisted `go list -deps` set is authoritative for package
	// absence only when it is an admitted complete inventory whose context
	// matches the snapshot — a failed, incomplete or untyped list cannot
	// distinguish "not linked" from "not measured".
	imports, inventoryID, impErr := packageImportSet(c)
	if impErr != nil {
		message := "package-absence check unavailable: " + impErr.Error()
		limitations = append(limitations, message)
		m.AnalysisGaps = append(m.AnalysisGaps, rootCauseAnalysisGap(domain.GapOwnerInput,
			domain.GapInputResolutionFailed, domain.ObligationPackagePresence, message))
	}
	// One admitted absence result per input bundle. The model must be complete
	// before it is derived — every in-scope candidate's identity observation
	// (coordinate resolution and the exact-preimage route) is established
	// first — because an admission computed from a half-populated model would
	// answer a different question than the replay of the same case.
	var inScope []domain.RootCause
	for i := range m.RootCauses {
		rc := m.RootCauses[i]
		if !inAffectedPackages(rc, v) {
			m.Alternatives = append(m.Alternatives, rc)
			continue
		}
		// A candidate may be modelled only when it names an established
		// subject of the selected version: a record-declared subject, an
		// operator-supplied subject, an LLM hypothesis with its own
		// consumer-side admission, or a fix-derived candidate whose
		// module-relative patch coordinate resolves in that version's own
		// source. A guessed coordinate from another release line is unmapped —
		// its package was never a subject of this version, so "not linked into
		// the product" says nothing about it.
		rc, gap := vf.establishBinding(c, v, m, rc)
		// The model must carry the binding its own identity gate re-reads: the
		// shared admission re-derives the same-line record from these bytes.
		if i < len(m.RootCauses) {
			m.RootCauses[i] = rc
		}
		if gap != nil {
			m.AnalysisGaps = append(m.AnalysisGaps, *gap)
		}
		inScope = append(inScope, rc)
	}
	var build domain.AbsenceBuildGraph
	if impErr == nil {
		build = domain.AbsenceBuildGraph{Paths: imports, EvidenceID: inventoryID, Admitted: true}
	} else {
		build = domain.AbsenceBuildGraph{Reason: impErr.Error()}
	}
	var affected *domain.AffectedResult
	if c != nil {
		affected = c.Affected
	}
	proof := fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), m)
	absenceAdmission := domain.AdmitAbsenceFor(m, v, affected, recordPin(c), nil, build, proof)

	verified := make([]domain.RootCause, 0, len(inScope))
	for _, rc := range inScope {
		identity := domain.CandidateSubjectIdentity(rc, v)
		if !identity.Admitted {
			message := "candidate " + rc.Package + "." + rc.Symbol + " unverified: " + identity.Reason
			limitations = append(limitations, message)
			m.Alternatives = append(m.Alternatives, rc)
			m.Unverified = append(m.Unverified, rc)
			continue
		}
		if rc.Binding != nil && rc.Binding.Status == domain.CandidateBindingUnmapped {
			limitations = append(limitations, fmt.Sprintf(
				"candidate %s.%s is unmapped in the selected version's source: %s; the subject is record-declared, so its absence stays evidence about a declared subject",
				rc.Package, rc.Symbol, rc.Binding.Detail))
		}
		// Package absence is then decided from the admitted complete product
		// closure BEFORE any product-independent source lookup. A symbol that
		// loads from the module cache or the vendor tree is still absent from
		// the product when its package never entered the build graph: existing
		// in dependency source is not being linked into the product. Only the
		// decoded build graph may say so — a loader failure measured nothing
		// about the package, so it never reaches this branch as absence.
		//
		// Naming the subject is not enough to conclude its absence: the
		// negative needs an affirmative admitted basis from the single
		// admission, so a resolved patch coordinate or an origin label alone
		// refuses here. The bases that do admit are the record's own
		// declaration, a re-admitted own-record operation binding, and the
		// exact-preimage route, whose necessity cover is then checked before
		// any absence is recorded.
		if impErr == nil && rc.Package != "" && !imports[rc.Package] {
			subject := domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol}
			// The same-line route carries its own necessity cover: the defect
			// can only execute in one of the declared packages. A single linked
			// member therefore contradicts the absence conclusion — the code
			// that could carry the defect is in the product — so the candidate
			// stays a blocking obligation instead of becoming absence evidence.
			if reason := absenceAdmission.CoverBuildRefusal(subject); reason != "" {
				message := fmt.Sprintf("candidate %s.%s is not resolved by absence: %s", rc.Package, rc.Symbol, reason)
				limitations = append(limitations, message)
				m.Alternatives = append(m.Alternatives, rc)
				m.Unverified = append(m.Unverified, rc)
				m.AnalysisGaps = append(m.AnalysisGaps, *bindingGap(domain.GapOwnerCode,
					domain.GapRootCauseUnresolved, reason))
				continue
			}
			if admission := absenceAdmission.Admits(subject); !admission.Admitted {
				message := fmt.Sprintf(
					"candidate %s.%s is not resolved by absence: %s", rc.Package, rc.Symbol, admission.Reason)
				limitations = append(limitations, message)
				m.Alternatives = append(m.Alternatives, rc)
				m.Unverified = append(m.Unverified, rc)
				m.AnalysisGaps = append(m.AnalysisGaps, *bindingGap(domain.GapOwnerCode,
					domain.GapRootCauseUnresolved, admission.Reason))
				continue
			}
			rc.Absent = true
			rc.EvidenceIDs = appendUniqueEvidenceID(rc.EvidenceIDs, inventoryID)
			verified = append(verified, rc)
			limitations = append(limitations, fmt.Sprintf(
				"candidate %s.%s resolved by absence: package %s not in the admitted product build graph (evidence %s)",
				rc.Package, rc.Symbol, rc.Package, inventoryID))
			continue
		}
		lk, err := vf.Source.LookupSymbol(ctx, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
		if err != nil {
			message := lookupLimitation(rc, lk, err)
			limitations = append(limitations, message)
			m.AnalysisGaps = append(m.AnalysisGaps, rootCauseAnalysisGap(domain.GapOwnerProof,
				domain.GapProofArtifactMissing, domain.ObligationRootCause,
				"candidate source verification failed: "+message))
			m.Alternatives = append(m.Alternatives, rc)
			m.Unverified = append(m.Unverified, rc)
			continue
		}
		if lk.Vendored {
			limitations = append(limitations, fmt.Sprintf(
				"symbol %s.%s verified against vendored source (Go loader unavailable: %v)",
				rc.Package, rc.Symbol, lk.LoaderError))
		}
		verified = append(verified, rc)
	}
	m.RootCauses = verified
	if len(verified) == 0 && len(m.Alternatives) > 0 {
		m.Status = domain.RootCauseAmbiguous
		m.RootCauses = nil
		m.AnalysisGaps = append(m.AnalysisGaps, rootCauseAnalysisGap(domain.GapOwnerCode,
			domain.GapRootCauseUnresolved, domain.ObligationRootCause,
			"every root-cause candidate failed source verification or fell outside the affected packages"))
	}
	return limitations
}

// lookupLimitation names the evidence gap behind an unresolved candidate. A
// loader failure measured nothing about the package, so the text must not
// read like a negative result; only a typed or vendored answer can say the
// symbol is not declared.
func lookupLimitation(rc domain.RootCause, lk goanalysis.SymbolLookup, err error) string {
	if lk.LoaderError != nil {
		return fmt.Sprintf(
			"candidate %s.%s unverified: Go loader failed for the package and no vendored source declares the symbol (%v)",
			rc.Package, rc.Symbol, err)
	}
	return fmt.Sprintf("candidate %s.%s not found in source: %v", rc.Package, rc.Symbol, err)
}

// appendUniqueEvidenceID adds id to ids once: verification may be re-run
// against the same model, and the inventory citation must not accumulate.
func appendUniqueEvidenceID(ids []domain.EvidenceID, id domain.EvidenceID) []domain.EvidenceID {
	if id == "" {
		return ids
	}
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}

// packageImportSet returns the import-path set of the admitted package-list
// inventory: evidence recorded as completed and complete, whose build
// context matches the snapshot, and whose content decodes as a complete,
// edge-closed graph. Anything less cannot ground absence — RootCause.Absent
// is only ever set from this set.
func packageImportSet(c *domain.AnalysisCase) (map[string]bool, domain.EvidenceID, error) {
	if c == nil {
		return nil, "", fmt.Errorf("no package-list evidence")
	}
	e, err := domain.SelectCompletePackageList(c.Product, c.EvidenceGraph.EvidenceList())
	if err != nil {
		return nil, "", err
	}
	inv, err := affected.CompletePackageInventory([]byte(e.Content), e.Command)
	if err != nil {
		return nil, "", fmt.Errorf("package list %s is not a complete inventory: %w", e.ID, err)
	}
	return inv.Paths, e.ID, nil
}

func inAffectedPackages(rc domain.RootCause, v domain.Vulnerability) bool {
	if len(v.AffectedPackages) == 0 {
		return true // no constraint recorded
	}
	for _, p := range v.AffectedPackages {
		if p.Path == rc.Package {
			return true
		}
	}
	return false
}

func matchSymbolRef(s1, s2 string) bool {
	norm := func(s string) string {
		s = strings.TrimPrefix(s, "(*")
		s = strings.TrimPrefix(s, "*")
		s = strings.ReplaceAll(s, ")*", "")
		s = strings.ReplaceAll(s, ")", "")
		s = strings.ReplaceAll(s, "(", "")
		return s
	}
	n1, n2 := norm(s1), norm(s2)
	return n1 == n2 || strings.HasSuffix(n1, "."+n2) || strings.HasSuffix(n2, "."+n1)
}

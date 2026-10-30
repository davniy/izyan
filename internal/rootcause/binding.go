package rootcause

import (
	"fmt"
	"slices"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// establishBinding derives a candidate's identity observation in the selected
// version's own source: the coordinate resolution and, for fix material, the
// exact-preimage route record. The absence decision itself is never made here —
// the caller derives one shared domain.AbsenceAdmission from the completed model
// and asks it.
//
// Identity before absence: a candidate derived from fix material must resolve
// its module-relative patch coordinate in the source of the module version the
// affected chain actually selected. A candidate whose coordinate does not exist
// there names no subject of that version at all — its absence from the product
// closure is vacuous and must never become RootCause.Absent. Nothing weaker
// than the same module-relative path is accepted: a matching function name,
// path suffix or literal does not establish identity.
//
// The second result is the typed cause to record when the prerequisite was
// missing (no selected-source input) or the correspondence could not be
// established — the caller records it as an analysis gap so the assessment
// fails as analyzer work rather than closing as an environmental abstention.
func (vf Verifier) establishBinding(c *domain.AnalysisCase, v domain.Vulnerability,
	m *domain.RootCauseModel, rc domain.RootCause) (domain.RootCause, *domain.AnalysisGap) {

	subject := domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol}
	// Candidates the record itself declares need no version binding: their
	// identity is the advisory entry. A fix-derived candidate always does,
	// even when a (legacy) model persisted none.
	if rc.Binding == nil && rc.Origin != domain.RootCauseOriginFixDerived {
		return rc, nil
	}

	modulePath := v.Module
	patchPath := ""
	if rc.Binding != nil {
		if rc.Binding.Module != "" {
			modulePath = rc.Binding.Module
		}
		patchPath = rc.Binding.PatchPath
	}
	binding := domain.CandidateBinding{
		Module:    modulePath,
		Version:   selectedVersion(c, modulePath),
		PatchPath: patchPath,
	}
	recordDeclared := domain.RecordDeclaresSubject(v, subject)

	var gap *domain.AnalysisGap
	switch {
	case patchPath == "":
		binding.Status = domain.CandidateBindingUnmeasured
		binding.Detail = "the candidate records no module-relative patch coordinate, so no correspondence into the selected source can be established"
		gap = bindingGap(domain.GapOwnerCode, domain.GapRootCauseUnresolved, binding.Detail)
	default:
		resolution := resolveCoordinate(vf.Source, c, modulePath, patchPath)
		binding.Version = resolution.Version
		gap = vf.applyBindingOutcome(&binding, patchPath, recordDeclared, resolution)
		// A resolved coordinate is existence, not correspondence. The
		// exact-preimage route is what establishes which declaration the change
		// is about, so it runs here and its typed outcome is recorded on the
		// binding — including its refusals, which are what stops a guessed
		// function name from grounding anything.
		if rc.Origin == domain.RootCauseOriginFixDerived && resolution.resolved() && resolution.Exists {
			binding.SameLine = vf.sameLineCorrespondence(c, v, m, modulePath, patchPath)
		}
	}
	rc.Binding = &binding
	return rc, gap
}

// applyBindingOutcome records one selected-source coordinate resolution on the
// candidate binding and returns the typed cause the caller must record, if any.
func (vf Verifier) applyBindingOutcome(binding *domain.CandidateBinding, patchPath string,
	recordDeclared bool, resolution coordinateResolution) *domain.AnalysisGap {
	switch {
	case !resolution.resolved():
		binding.Status = domain.CandidateBindingUnmeasured
		binding.Detail = resolution.Reason
		if resolution.InputFailure {
			return bindingGap(domain.GapOwnerInput, domain.GapInputResolutionFailed, binding.Detail)
		}
		return bindingGap(domain.GapOwnerCode, domain.GapRootCauseUnresolved, binding.Detail)
	case resolution.Exists:
		binding.SourceKind = string(resolution.Source.Selection.SourceKind)
		binding.Status = domain.CandidateBindingAdmitted
		binding.Detail = fmt.Sprintf("patch coordinate %s resolves in the selected source of %s",
			patchPath, resolution.Source.Label())
		return nil
	default:
		binding.SourceKind = string(resolution.Source.Selection.SourceKind)
		binding.Status = domain.CandidateBindingUnmapped
		binding.Detail = fmt.Sprintf("patch coordinate %s does not exist in the selected source of %s",
			patchPath, resolution.Source.Label())
		if !recordDeclared {
			return bindingGap(domain.GapOwnerCode, domain.GapRootCauseUnresolved, binding.Detail)
		}
		return nil
	}
}

// recordedEffectiveSource returns the effective-source descriptor the affected
// chain captured for modulePath. Multiple descriptors naming the same module
// path are ambiguous, so none is used and the caller falls back to the
// recorded build environment.
func recordedEffectiveSource(c *domain.AnalysisCase, modulePath string) *domain.EffectiveSourceSelection {
	if c == nil || c.Affected == nil || modulePath == "" {
		return nil
	}
	var found *domain.EffectiveSourceSelection
	for i := range c.Affected.EffectiveSources {
		selection := c.Affected.EffectiveSources[i]
		if selection.DeclaredModule != modulePath {
			continue
		}
		if found != nil {
			return nil
		}
		copied := selection
		found = &copied
	}
	return found
}

// recordPin returns the case's record pin, or nil when there is no case to read
// it from. A nil pin refuses every own-record operation binding rather than
// trusting a persisted one.
func recordPin(c *domain.AnalysisCase) *domain.RecordPin {
	if c == nil {
		return nil
	}
	return c.RecordPin
}

// bindingGap records the typed cause that keeps a candidate's identity (and so
// its absence evidence) unresolved.
func bindingGap(owner domain.GapOwner, code domain.GapCode, message string) *domain.AnalysisGap {
	return &domain.AnalysisGap{
		Owner:      owner,
		Code:       code,
		Obligation: domain.ObligationRootCause,
		Message:    "candidate identity unresolved against the selected version's source: " + message,
	}
}

// patchCoordinate records the module-relative patch coordinate a fix-derived
// candidate was read from. The status is deliberately unmeasured: identity is
// derived later, against the selected version's own source — never from the
// patch path alone.
func patchCoordinate(v domain.Vulnerability, patchPath string) *domain.CandidateBinding {
	return &domain.CandidateBinding{
		Status:    domain.CandidateBindingUnmeasured,
		Module:    v.Module,
		PatchPath: strings.TrimSpace(patchPath),
	}
}

// selectedVersion returns the resolved version the affected chain recorded for
// modulePath. A resolved version belonging to a different module never answers:
// substituting another entry's version would bind the candidate to source it was
// not derived from.
func selectedVersion(c *domain.AnalysisCase, modulePath string) string {
	if c == nil || c.Affected == nil || modulePath == "" {
		return ""
	}
	resolved := c.Affected.ResolvedVersion
	if resolved == "" {
		return ""
	}
	if c.Affected.SelectedModule != "" && c.Affected.SelectedModule != modulePath {
		return ""
	}
	if len(c.Affected.SelectedModules) > 0 && !slices.Contains(c.Affected.SelectedModules, modulePath) {
		return ""
	}
	return resolved
}

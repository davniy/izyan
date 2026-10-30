package rootcause

import (
	"fmt"
	"sort"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/fixbinding"
)

// This file is the verifier side of the exact-preimage correspondence route. It
// supplies the captured inputs the pure checker cannot read — the selected
// version's own file bytes and the model's captured artifact bytes — and turns
// its typed measurement into a decision the absence branch can act on.
//
// Nothing here is authority by itself. The route establishes identity (which
// declaration the change is about) and the necessity boundary (which packages
// the defect could execute in); whether the subject may ground an absence claim
// is still decided by the single shared admission in domain.AbsenceAdmission,
// which re-derives the preimage digest from the same captured bytes.

// sameLineCorrespondence runs the exact-preimage route for one fix-derived
// candidate. It returns nil when the route is not measurable: no selected
// source, no selected-source file at the coordinate, no captured bytes for the
// changed path, or no artifact whose complete before-image matched. A nil result
// keeps the candidate on its previous, non-admitting path.
func (vf Verifier) sameLineCorrespondence(c *domain.AnalysisCase, v domain.Vulnerability,
	m *domain.RootCauseModel, modulePath, patchPath string) *domain.SameLineCorrespondence {

	if vf.Source == nil || m == nil || patchPath == "" || modulePath == "" {
		return nil
	}
	resolution := resolveCoordinate(vf.Source, c, modulePath, patchPath)
	if !resolution.resolved() || !resolution.Exists {
		return nil
	}
	selected, err := vf.Source.SelectedModuleFile(resolution.Source, patchPath)
	if err != nil || len(selected) == 0 {
		return nil
	}
	var affected *domain.AffectedResult
	if c != nil {
		affected = c.Affected
	}
	boundary := domain.DeclaredSubjectBoundary(v, affected, modulePath)

	var chosen *domain.SameLineCorrespondence
	var rejected *domain.SameLineCorrespondence
	var disagreement string
	for _, a := range capturedArtifactsFor(m, patchPath) {
		rec := fixbinding.MatchSameLinePreimage(fixbinding.SameLineInput{
			Locator:          a.Locator,
			Path:             patchPath,
			Module:           modulePath,
			Patch:            []byte(a.Bytes),
			Selected:         selected,
			DeclaredPackages: boundary,
		})
		if !rec.Covers() {
			if rejected == nil || rejected.Status.Covers() {
				copied := rec
				rejected = &copied
			}
			continue
		}
		if chosen == nil {
			copied := rec
			chosen = &copied
			continue
		}
		if chosen.OmissionSite != rec.OmissionSite || chosen.PreimageDigest != rec.PreimageDigest {
			disagreement = fmt.Sprintf(
				"the captured artifacts %s and %s both match %s but disagree about its subject, so no single declaration is the change's subject",
				chosen.Locator, a.Locator, patchPath)
		}
	}
	if disagreement != "" {
		return &domain.SameLineCorrespondence{
			Locator: chosen.Locator, Path: patchPath,
			Status: domain.SameLinePreimageAmbiguous, Detail: disagreement,
		}
	}
	if chosen != nil {
		return chosen
	}
	return rejected
}

// capturedArtifactsFor returns every captured artifact whose recorded inventory
// covers patchPath, with its bytes resolved through a duplicate reference and
// its digest re-checked. A row whose bytes no longer hash to its digest is
// dropped: it establishes nothing about the change.
func capturedArtifactsFor(m *domain.RootCauseModel, patchPath string) []domain.FixArtifact {
	if m == nil {
		return nil
	}
	byLocator := make(map[string]domain.FixArtifact, len(m.FixArtifacts))
	for _, a := range m.FixArtifacts {
		byLocator[a.Locator] = a
	}
	var out []domain.FixArtifact
	for _, a := range m.FixArtifacts {
		if !a.Outcome.Captured() {
			continue
		}
		changed := false
		for _, coord := range a.Coordinates {
			if coord == patchPath {
				changed = true
				break
			}
		}
		if !changed {
			continue
		}
		resolved, ok := byLocator[a.Locator]
		for guard := 0; ok && resolved.Bytes == "" && resolved.DuplicateOf != ""; guard++ {
			if guard > len(m.FixArtifacts) {
				ok = false
				break
			}
			resolved, ok = byLocator[resolved.DuplicateOf]
		}
		if !ok || resolved.Bytes == "" {
			continue
		}
		if resolved.Digest != "" && resolved.Digest != domain.EvidenceContentDigest(resolved.Bytes) {
			continue
		}
		out = append(out, resolved)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Locator < out[j].Locator })
	return out
}

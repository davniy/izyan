package rootcause

import (
 "context"
	"fmt"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fixbinding"
)

// proveContentBinding derives the persisted content proof for one advisory
// entry of this model and attaches it when — and only when — the pure checker
// reconstructs a cover from the captured inputs.
//
// This is the production producer of domain.FixProof. It supplies no summary:
// the advisory bytes come from the case's own capture, the effective-source
// descriptors and the anchored inventory come from the recorded build, the
// artifact bytes are the ones the provider returned, and the patch-side source
// is accepted only where a captured change's complete before-image matches the
// selected implementation exactly. Anything the analysis did not capture stays
// an explicit obligation, so the route refuses rather than approximates.
func (r Resolver) proveContentBinding(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability, model *domain.RootCauseModel) {
	if r.Source == nil || c == nil || c.Affected == nil || model == nil {
		return
	}
	if len(model.FixArtifacts) == 0 {
		return
	}
	if c.AdvisoryRecord == nil {
		model.Limitations = append(model.Limitations,
			"content binding not attempted: the advisory bytes were not captured, so no proof premise can be re-derived")
		return
	}
	if err := c.AdvisoryRecord.Validate(); err != nil {
		model.Limitations = append(model.Limitations,
			"content binding not attempted: the advisory capture does not validate: "+err.Error())
		return
	}

	artifacts := make([]fixbinding.ArtifactInput, 0, len(model.FixArtifacts))
	for _, a := range model.FixArtifacts {
		in := fixbinding.ArtifactInput{Artifact: a}
		if a.Bytes != "" {
			in.Bytes = []byte(a.Bytes)
		}
		artifacts = append(artifacts, in)
	}

	for _, sel := range c.Affected.EffectiveSources {
		if sel.Failure != nil || sel.SourceKind == "" {
			continue
		}
		census, err := r.Source.SelectedSourceCensusFor(sel)
		if err != nil {
			model.Limitations = append(model.Limitations, fmt.Sprintf(
				"content binding entry %d not attempted: the selected source could not be censused: %v", sel.EntryRef, err))
			continue
		}
  requested, err := r.Captures.requested(c,sel)
  if err != nil { model.Limitations=append(model.Limitations,"content binding capture refused: "+err.Error());continue }
  captures, err := r.Source.CaptureFixSources(ctx,c,sel,requested,r.GoTool)
  if err != nil { model.Limitations=append(model.Limitations,"content binding capture refused: "+err.Error());continue }
		in := fixbinding.Inputs{
			Pin:          c.AdvisoryRecord.Pin,
			Raw:          c.AdvisoryRecord.Bytes,
			EntryRef:     sel.EntryRef,
			Selection:    c.Affected.EffectiveSources,
			Inventory:    census.Inventory,
			Artifacts:    artifacts,
   Captures: &captures,
		}
  in, err = fixbinding.ReconstructSources(in)
  if err != nil { model.Limitations=append(model.Limitations,"content binding capture refused: "+err.Error());continue }
		// The semantic derivation is the specialized checker and runs only
		// after applicability is established from the captured material.
		// Material that changes no supported security operation stays an
		// observation: deriving a cover from it would account for prose, not
		// for a mechanism.
		if app := fixbinding.FixApplicability(in); !app.Applicable {
			model.Limitations = append(model.Limitations, fmt.Sprintf(
				"content binding entry %d is not applicable: %s", sel.EntryRef, app.Reason()))
			continue
		}
		binding, err := fixbinding.Derive(in)
		if err != nil {
			model.Limitations = append(model.Limitations, fmt.Sprintf(
				"content binding entry %d refused: %v", sel.EntryRef, err))
			continue
		}
		proof, err := fixbinding.Persist(fixbinding.AdmissionForCase(c), binding, in)
		if err != nil {
			model.Limitations = append(model.Limitations, fmt.Sprintf(
				"content binding entry %d refused at persistence: %v", sel.EntryRef, err))
			continue
		}
		model.FixProof = proof
		return
	}
}


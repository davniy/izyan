package rootcause

import (
	"context"
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fix"
)

// resolveFixArtifacts accounts for every fix locator the record declares and
// inventories every relevant captured artifact.
//
// The rule this replaces stopped at the first successfully fetched patch and
// turned every other declared locator into a missing-artifact obligation. That
// asserted unavailability nobody had established and blocked every
// multi-locator record. Here each distinct locator is requested exactly once,
// its outcome is typed, and only an artifact the configured provider was asked
// for and does not hold is reported as missing.
//
// The locators are not a patch series. A reference may be another release
// line's fix, an alternative representation, or unrelated material, and the
// record's aggregate fixed-version list names no particular reference. Nothing
// here orders them, applies one on top of another, or claims the set is
// complete.
func (r Resolver) resolveFixArtifacts(ctx context.Context, c *domain.AnalysisCase,
	v domain.Vulnerability, refs []fix.Reference, model *domain.RootCauseModel) []domain.Evidence {

	acquired := fix.AcquireAll(ctx, r.Patch, refs)
	for n := range acquired {
		acquired[n] = r.inventoryFixArtifact(acquired[n], c, v)
	}
	inheritDuplicateInventories(acquired)

	for _, a := range acquired {
		model.FixArtifacts = append(model.FixArtifacts, a.Record)
		if gap := artifactGap(a.Record); gap != nil {
			model.AnalysisGaps = append(model.AnalysisGaps, *gap)
		}
		if a.Record.Outcome != domain.FixArtifactComplete {
			model.Limitations = append(model.Limitations, fmt.Sprintf("fix artifact %s (%s): %s",
				a.Record.Locator, a.Record.Outcome, a.Record.Detail))
		}
	}

	for _, a := range acquired {
		if a.Body == "" {
			continue
		}
		r.deriveFixCandidates(ctx, v, a.Record.Locator, a.Body, model)
	}
	return fixArtifactEvidence(acquired)
}

// inventoryFixArtifact completes one acquisition record: it inventories the
// captured artifact's relevant changed coordinates and decides whether that
// material describes the analysed version. An artifact the provider did not
// deliver keeps its acquisition outcome: no applicability is claimed for bytes
// that were never captured.
func (r Resolver) inventoryFixArtifact(a fix.AcquiredArtifact, c *domain.AnalysisCase,
	v domain.Vulnerability) fix.AcquiredArtifact {

	record := a.Record
	if record.Outcome != domain.FixArtifactComplete || record.DuplicateOf != "" {
		return a
	}
	parsed := fix.Parse(a.Body)
	if len(parsed) == 0 {
		record.Outcome = domain.FixArtifactApplicabilityUnknown
		record.Detail = "the captured bytes carry no unified diff, so no changed coordinate could be inventoried"
		a.Record = record
		return a
	}
	coordinates := relevantCoordinates(parsed)
	record.Coordinates = coordinates
	if len(coordinates) == 0 {
		record.Detail = "the captured artifact changes no non-test Go source"
		a.Record = record
		return a
	}
	record.Outcome, record.Detail = r.classifyArtifactCoordinates(c, v, coordinates)
	a.Record = record
	return a
}

// classifyArtifactCoordinates decides whether a captured artifact describes the
// analysed version. It uses the same coordinate resolution as candidate
// identity, so an artifact cannot be reported applicable here and unmapped
// there.
func (r Resolver) classifyArtifactCoordinates(c *domain.AnalysisCase, v domain.Vulnerability,
	coordinates []string) (domain.FixArtifactOutcome, string) {

	mapped := 0
	var source domain.ResolvedModuleSource
	unresolved := ""
	for _, relPath := range coordinates {
		resolution := resolveCoordinate(r.Source, c, v.Module, relPath)
		if !resolution.resolved() {
			unresolved = fmt.Sprintf("coordinate %s could not be checked: %s", relPath, resolution.Reason)
			break
		}
		source = resolution.Source
		if resolution.Exists {
			mapped++
		}
	}
	if unresolved != "" {
		return domain.FixArtifactApplicabilityUnknown, unresolved
	}
	if mapped == 0 {
		return domain.FixArtifactUnmapped, fmt.Sprintf(
			"none of the %d changed coordinate(s) exists in the selected source of %s",
			len(coordinates), source.Label())
	}
	return domain.FixArtifactComplete, fmt.Sprintf(
		"%d of %d changed coordinate(s) resolve in the selected source of %s",
		mapped, len(coordinates), source.Label())
}

// inheritDuplicateInventories gives a locator whose bytes duplicate an earlier
// one the same inventory and applicability conclusion. The bytes are identical,
// so a second parse could only re-derive the same answer; the record keeps its
// own locator and provenance and must not double-count the artifact.
func inheritDuplicateInventories(acquired []fix.AcquiredArtifact) {
	byLocator := make(map[string]int, len(acquired))
	for n := range acquired {
		byLocator[acquired[n].Record.Locator] = n
	}
	for n := range acquired {
		record := &acquired[n].Record
		if record.DuplicateOf == "" {
			continue
		}
		primary, ok := byLocator[record.DuplicateOf]
		if !ok {
			continue
		}
		record.Coordinates = append([]string(nil), acquired[primary].Record.Coordinates...)
		record.Outcome = acquired[primary].Record.Outcome
		record.Detail = "byte-identical to the artifact captured for " + record.DuplicateOf
	}
}

// relevantCoordinates lists the module-relative non-test Go paths an artifact
// changes. Only these can carry a root cause of this module: another
// repository's paths, vendored inputs and test-only files are inventoried by
// the artifact record but contribute no subject.
func relevantCoordinates(parsed fix.Patch) []string {
	seen := make(map[string]bool, len(parsed))
	out := make([]string, 0, len(parsed))
	for _, f := range parsed {
		if !strings.HasSuffix(f.Path, ".go") || isTestFile(f.Path) || seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		out = append(out, f.Path)
	}
	return out
}

// deriveFixCandidates records every function the captured artifact changes,
// plus the selected source's enclosing function at each changed line. It is
// deliberately additive: candidates from an artifact that does not resolve in
// the selected version stay on the model as unverified obligations rather than
// disappearing, and the verifier — not this function — decides identity.
func (r Resolver) deriveFixCandidates(ctx context.Context, v domain.Vulnerability,
	locator, patch string, model *domain.RootCauseModel) {

	for _, f := range fix.Parse(patch) {
		if !strings.HasSuffix(f.Path, ".go") || isTestFile(f.Path) {
			continue
		}
		pkg := packageGuess(v, f.Path)
		for _, sym := range f.Symbols {
			addFixAlternative(model, domain.RootCause{
				Package:   pkg,
				Symbol:    sym,
				Role:      domain.RootCauseSink,
				Mechanism: fmt.Sprintf("changed by fix artifact %s", locator),
				Origin:    domain.RootCauseOriginFixDerived,
				Binding:   patchCoordinate(v, f.Path),
			})
		}
		if r.Source == nil {
			continue
		}
		for _, line := range f.HunkLines {
			enc, err := r.Source.EnclosingFuncAt(ctx, pkg, f.Path, line)
			if err != nil || enc.Symbol == "" {
				continue
			}
			addFixAlternative(model, domain.RootCause{
				Package:   enc.Package,
				Symbol:    enc.Symbol,
				Role:      domain.RootCauseSink,
				Mechanism: fmt.Sprintf("enclosing function at hunk line %d in fix artifact %s", line, locator),
				Origin:    domain.RootCauseOriginFixDerived,
				Binding:   patchCoordinate(v, f.Path),
			})
		}
	}
}

// addFixAlternative appends one fix-derived candidate once. Two artifacts that
// change the same function name it once, so the model does not grow a second
// subject for one source locus.
func addFixAlternative(model *domain.RootCauseModel, candidate domain.RootCause) {
	for _, existing := range model.Alternatives {
		if existing.Package == candidate.Package && existing.Symbol == candidate.Symbol {
			return
		}
	}
	model.Alternatives = append(model.Alternatives, candidate)
}

// fixArtifactEvidence returns the FIX_DIFF evidence for the captured artifact
// that best evidences this version's fix: the first artifact whose changed
// coordinates resolve in the selected source, and failing that the first
// captured artifact in declaration order. One evidence record keeps the
// case-level "this is the fix diff" contract its consumers rely on, while every
// locator's own account — provenance, digest, inventory and outcome — stays on
// the model.
func fixArtifactEvidence(acquired []fix.AcquiredArtifact) []domain.Evidence {
	applicable, captured := -1, -1
	for n := range acquired {
		record := acquired[n].Record
		if !record.Outcome.Captured() || acquired[n].Body == "" {
			continue
		}
		if captured < 0 {
			captured = n
		}
		if record.Outcome == domain.FixArtifactComplete && len(record.Coordinates) > 0 {
			applicable = n
			break
		}
	}
	choice := applicable
	if choice < 0 {
		choice = captured
	}
	if choice < 0 {
		return nil
	}
	record := acquired[choice].Record
	return []domain.Evidence{{
		Kind:    domain.EvidenceFixDiff,
		Quality: domain.QualityAuthoritative,
		Source:  record.Locator,
		Tool:    "fix.HTTPProvider",
		Content: truncate(acquired[choice].Body, 64<<10),
	}}
}

// artifactGap states the typed obligation one artifact outcome leaves, if any.
// The mapping follows what was actually established and nothing else:
//
//   - the provider was asked and holds no bytes: PROOF / PROOF_ARTIFACT_MISSING,
//     the only case that may claim a required artifact is missing;
//   - the configured provider cannot acquire this locator's form, or could not
//     answer at all: INPUT / INPUT_RESOLUTION_FAILED — a capability gap, so the
//     artifact's availability stays unestablished;
//   - the bytes are present but map onto no coordinate of the selected source,
//     or their applicability could not be established: CODE /
//     ROOT_CAUSE_UNRESOLVED — analyzer work, never a claim of missing bytes.
func artifactGap(record domain.FixArtifact) *domain.AnalysisGap {
	var owner domain.GapOwner
	var code domain.GapCode
	var message string
	switch record.Outcome {
	case domain.FixArtifactComplete:
		return nil
	case domain.FixArtifactUnavailable:
		owner, code = domain.GapOwnerProof, domain.GapProofArtifactMissing
		message = "fix artifact " + record.Locator + " is unavailable: " + record.Detail
	case domain.FixArtifactUnsupportedAcquisition:
		owner, code = domain.GapOwnerInput, domain.GapInputResolutionFailed
		message = "fix artifact " + record.Locator + " cannot be acquired by the configured provider: " + record.Detail
	case domain.FixArtifactAcquisitionFailed:
		owner, code = domain.GapOwnerInput, domain.GapInputResolutionFailed
		message = "fix artifact " + record.Locator + " could not be acquired: " + record.Detail
	case domain.FixArtifactUnmapped:
		owner, code = domain.GapOwnerCode, domain.GapRootCauseUnresolved
		message = "fix artifact " + record.Locator + " is available but describes no coordinate of the analysed version: " + record.Detail
	case domain.FixArtifactApplicabilityUnknown:
		owner, code = domain.GapOwnerCode, domain.GapRootCauseUnresolved
		message = "fix artifact " + record.Locator + " is available but its applicability to the analysed version is unknown: " + record.Detail
	default:
		owner, code = domain.GapOwnerCode, domain.GapRootCauseUnresolved
		message = "fix artifact " + record.Locator + " carries an unclassified acquisition outcome " + string(record.Outcome)
	}
	return &domain.AnalysisGap{
		Owner:      owner,
		Code:       code,
		Obligation: domain.ObligationRootCause,
		Message:    message,
	}
}

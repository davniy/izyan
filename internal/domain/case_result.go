package domain

import "fmt"

// ValidateCaseResult is the package-level form of the result contract check.
func ValidateCaseResult(c *AnalysisCase) error {
	if c == nil {
		return fmt.Errorf("analysis case: nil case")
	}
	return c.ValidateCaseResult()
}

// ValidateFinalizedCase is the package-level form of the publication gate.
func ValidateFinalizedCase(c *AnalysisCase) error {
	if c == nil {
		return fmt.Errorf("analysis case: nil case")
	}
	return c.ValidateFinalizedCase()
}

// Terminal reports whether the workflow state ends the run. Only a terminal
// state may be published: an intermediate state still has analysis,
// composition or reporting work left.
func (s WorkflowState) Terminal() bool {
	switch s {
	case StateCompleted, StateInconclusive, StateFailed:
		return true
	default:
		return false
	}
}

// HasRequestContractFields reports whether the case carries any
// analysis-case/2 request-level field. A terminal case with such a field but
// without the schema discriminator is a new-contract result masquerading as a
// legacy one; it may not be read as legacy.
func (c *AnalysisCase) HasRequestContractFields() bool {
	if c == nil {
		return false
	}
	return c.RequestedFinding != nil ||
		c.RelatedDiscovery != nil ||
		len(c.RelatedRecords) > 0 ||
		len(c.Attributions) > 0 ||
		c.CorpusDeclaration != nil ||
		c.CorpusManifest != nil
}

// ValidateCaseResult enforces the structural invariants a persisted case
// result must satisfy on every save and load:
//
//   - an unknown schema is rejected;
//   - analysis-case/2 always carries a requested-finding envelope, and a
//     terminal v2 case carries a FINAL one;
//   - an empty schema is a legacy (or still-pending) single-assessment case:
//     it may not carry a requested-finding envelope, and a terminal case with
//     request-level fields is rejected instead of being reinterpreted;
//   - record pins, corpus records, attributions, discovery, profile
//     assessments and related children are structurally valid.
//
// Pending roots remain loadable and resumable. Publication is a separate
// gate: ValidateFinalizedCase.
func (c *AnalysisCase) ValidateCaseResult() error {
	if c == nil {
		return fmt.Errorf("analysis case: nil case")
	}
	if c.Schema != "" && !c.Schema.Valid() {
		return fmt.Errorf("analysis case %q: unknown schema %q", c.ID, c.Schema)
	}
	switch c.Schema {
	case "":
		if c.RequestedFinding != nil {
			return fmt.Errorf("analysis case %q: a requested_finding envelope requires schema %s",
				c.ID, CaseSchemaV2)
		}
		if c.Workflow.State.Terminal() && c.HasRequestContractFields() {
			return fmt.Errorf("analysis case %q: terminal case carries analysis-case/2 request fields without the %s discriminator",
				c.ID, CaseSchemaV2)
		}
	case CaseSchemaV2:
		if c.RequestedFinding == nil {
			return fmt.Errorf("analysis case %q: schema %s requires a requested_finding envelope",
				c.ID, CaseSchemaV2)
		}
		if c.Workflow.State.Terminal() && c.RequestedFinding.Status != FindingFinal {
			return fmt.Errorf("analysis case %q: terminal schema %s result requires a FINAL requested finding, got %q",
				c.ID, CaseSchemaV2, c.RequestedFinding.Status)
		}
	}
	return c.validateRecordResult()
}

// validateRecordResult validates one case record without recursing into its
// related-record children, so a crafted or cyclic case cannot drive validation
// arbitrarily deep.
func (c *AnalysisCase) validateRecordResult() error {
	if c.Schema != "" && !c.Schema.Valid() {
		return fmt.Errorf("analysis case %q: unknown schema %q", c.ID, c.Schema)
	}
	if c.Schema == CaseSchemaV2 && c.RequestedFinding == nil {
		return fmt.Errorf("analysis case %q: schema %s requires a requested_finding envelope",
			c.ID, CaseSchemaV2)
	}
	if c.RecordPin != nil {
		if err := c.RecordPin.Validate(); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
	}
	if c.AdvisoryRecord != nil {
		if err := c.AdvisoryRecord.Validate(); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
		if c.RecordPin != nil && !c.RecordPin.Same(c.AdvisoryRecord.Pin) {
			return fmt.Errorf("analysis case %q: advisory record capture %q does not pin the case record %q",
				c.ID, c.AdvisoryRecord.Pin.RecordID, c.RecordPin.RecordID)
		}
	}
	if c.Affected != nil {
		for n := range c.Affected.EffectiveSources {
			sel := c.Affected.EffectiveSources[n]
			if err := sel.Validate(); err != nil {
				return fmt.Errorf("analysis case %q: %w", c.ID, err)
			}
			if n > 0 && sel.EntryRef <= c.Affected.EffectiveSources[n-1].EntryRef {
				return fmt.Errorf("analysis case %q: effective source entry refs are not strictly ordered at position %d", c.ID, n)
			}
		}
	}
	if c.RootCause != nil {
		if err := ValidateFixArtifacts(c.RootCause.FixArtifacts); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
	}
	if c.CorpusDeclaration != nil {
		if err := c.CorpusDeclaration.Validate(); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
	}
	if c.CorpusManifest != nil {
		if err := c.CorpusManifest.Validate(); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
	}
	for n := range c.Attributions {
		if err := c.Attributions[n].Validate(); err != nil {
			return fmt.Errorf("analysis case %q attributions[%d]: %w", c.ID, n, err)
		}
	}
	if c.RequestedFinding != nil {
		if err := c.RequestedFinding.Validate(); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
	}
	if c.RelatedDiscovery != nil {
		if err := c.RelatedDiscovery.Validate(); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
		if c.RequestedFinding != nil && c.RelatedDiscovery.RequestedID != c.RequestedFinding.RequestedID {
			return fmt.Errorf("analysis case %q: discovery requested id %q != requested finding id %q",
				c.ID, c.RelatedDiscovery.RequestedID, c.RequestedFinding.RequestedID)
		}
	}
	if c.PerimeterAssessment != nil {
		if err := c.PerimeterAssessment.Validate(); err != nil {
			return fmt.Errorf("analysis case %q: %w", c.ID, err)
		}
	}
	if err := validateAnalysisGaps(fmt.Sprintf("analysis case %q gaps", c.ID), c.AnalysisGaps); err != nil {
		return err
	}
	for n, profile := range c.ProfileAssessments {
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("analysis case %q profile_assessments[%d]: %w", c.ID, n, err)
		}
	}
	for n, related := range c.RelatedRecords {
		if related.ID == "" {
			return fmt.Errorf("analysis case %q related_records[%d]: assessment id is required", c.ID, n)
		}
		if err := related.Record.Validate(); err != nil {
			return fmt.Errorf("analysis case %q related_records[%d]: %w", c.ID, n, err)
		}
		if related.Analysis == nil {
			continue
		}
		if related.Analysis.ID != related.ID {
			return fmt.Errorf("analysis case %q related_records[%d]: nested case id %q != assessment id %q",
				c.ID, n, related.Analysis.ID, related.ID)
		}
		if err := related.Analysis.validateRecordResult(); err != nil {
			return fmt.Errorf("analysis case %q related_records[%d]: %w", c.ID, n, err)
		}
	}
	return nil
}

// ValidateFinalizedCase is the publication gate: it enforces everything
// ValidateCaseResult does plus the shape only a composed request can have.
// Publication authority is the requested-finding envelope status (FINAL), not
// the state-machine position: composition finalizes the envelope before
// BUILD_REPORT writes the report, and the workflow reaches its terminal state
// only afterwards. A legacy single-assessment case, a case without a composed
// envelope, and a case whose envelope is still PENDING are not publishable.
//
// The gate is structural. Re-admission of the proof artifacts behind the
// conclusion is finding.Project's job; neither gate may be skipped.
func (c *AnalysisCase) ValidateFinalizedCase() error {
	if c == nil {
		return fmt.Errorf("analysis case: nil case")
	}
	if c.Schema != CaseSchemaV2 {
		return fmt.Errorf("analysis case %q: schema %q has no analysis-case/2 requested finding and is not publishable through the requested-finding projection",
			c.ID, c.Schema)
	}
	if err := c.ValidateCaseResult(); err != nil {
		return err
	}
	requested := c.RequestedFinding
	if requested == nil {
		return fmt.Errorf("analysis case %q: schema %s requires a requested_finding envelope",
			c.ID, CaseSchemaV2)
	}
	if requested.Status != FindingFinal {
		return fmt.Errorf("analysis case %q: requested finding status %q is not publishable", c.ID, requested.Status)
	}
	if requested.PrimaryAssessmentID != c.ID {
		return fmt.Errorf("analysis case %q: requested finding names primary assessment %q",
			c.ID, requested.PrimaryAssessmentID)
	}
	requestedID, kind, coverage := RequestedIdentity(c)
	if requested.RequestedID != requestedID {
		return fmt.Errorf("analysis case %q: requested finding names request %q, the case resolves %q",
			c.ID, requested.RequestedID, requestedID)
	}
	if requested.RequestedKind != kind {
		return fmt.Errorf("analysis case %q: requested finding kind %q, the case resolves %q",
			c.ID, requested.RequestedKind, kind)
	}
	if requested.Coverage != coverage {
		return fmt.Errorf("analysis case %q: requested finding coverage %q, the case resolves %q",
			c.ID, requested.Coverage, coverage)
	}
	if !requested.IsTargetActual {
		return fmt.Errorf("analysis case %q: the publication projection must carry the deployment's actual profile", c.ID)
	}
	if len(c.ProfileAssessments) > 0 {
		actual, ok := targetActualProfile(c)
		if !ok {
			return fmt.Errorf("analysis case %q: profile assessments carry no unique target-actual profile", c.ID)
		}
		if requested.Profile != actual.Profile {
			return fmt.Errorf("analysis case %q: requested finding profile %q is not the target-actual profile %q",
				c.ID, requested.Profile, actual.Profile)
		}
	}
	return c.validateFinalChildren()
}

// targetActualProfile returns the one profile assessment marked as the
// deployment's actual profile. Zero or several marked assessments are a
// malformed record assessment.
func targetActualProfile(c *AnalysisCase) (ProfileAssessment, bool) {
	var found ProfileAssessment
	count := 0
	for _, profile := range c.ProfileAssessments {
		if !profile.IsTargetActual {
			continue
		}
		found = profile
		count++
	}
	if count != 1 {
		return ProfileAssessment{}, false
	}
	return found, true
}

// validateFinalChildren enforces the child rules of a finalized root: children
// are exact-record assessments, never nested discovery or request runners; an
// evaluated candidate always carries its own finalized envelope; an explicit
// unassessed disposition may carry only a partial (never a forged final) child.
func (c *AnalysisCase) validateFinalChildren() error {
	if len(c.RelatedRecords) > 0 && c.RelatedDiscovery == nil {
		return fmt.Errorf("analysis case %q: related assessments require a discovery record", c.ID)
	}
	if c.RelatedDiscovery == nil {
		return nil
	}
	dispositions := make(map[string]CandidateDisposition, len(c.RelatedDiscovery.Candidates))
	for _, candidate := range c.RelatedDiscovery.Candidates {
		dispositions[pinKey(candidate.Record)] = candidate.Disposition
	}
	children := make(map[string]*AnalysisCase, len(c.RelatedRecords))
	ids := make(map[CaseID]bool, len(c.RelatedRecords))
	for n, related := range c.RelatedRecords {
		if ids[related.ID] {
			return fmt.Errorf("analysis case %q related_records[%d]: assessment id %q is listed twice",
				c.ID, n, related.ID)
		}
		ids[related.ID] = true
		disposition, nominated := dispositions[pinKey(related.Record)]
		if !nominated {
			return fmt.Errorf("analysis case %q related_records[%d]: record %q (%s) was never nominated by discovery",
				c.ID, n, related.Record.RecordID, related.Record.DocumentDigest)
		}
		if related.Analysis == nil {
			if disposition == DispositionEvaluated {
				return fmt.Errorf("analysis case %q: evaluated candidate %q carries no independent assessment",
					c.ID, related.Record.RecordID)
			}
			continue
		}
		if _, duplicate := children[pinKey(related.Record)]; duplicate {
			return fmt.Errorf("analysis case %q: candidate %q (%s) carries two independent assessments",
				c.ID, related.Record.RecordID, related.Record.DocumentDigest)
		}
		children[pinKey(related.Record)] = related.Analysis
		if err := validateFinalChild(c, related, disposition); err != nil {
			return err
		}
	}
	for _, candidate := range c.RelatedDiscovery.Candidates {
		if candidate.Disposition != DispositionEvaluated {
			continue
		}
		if children[pinKey(candidate.Record)] == nil {
			return fmt.Errorf("analysis case %q: evaluated candidate %q (%s) has no independent assessment",
				c.ID, candidate.Record.RecordID, candidate.Record.DocumentDigest)
		}
	}
	return nil
}

// pinKey canonicalizes a record pin the same way RecordPin.Same compares it:
// the same record id and the same raw bytes are the same document even when
// the locator differs.
func pinKey(pin RecordPin) string {
	return pin.RecordID + "\x00" + pin.DocumentDigest
}

func validateFinalChild(root *AnalysisCase, related RelatedRecordAssessment, disposition CandidateDisposition) error {
	child := related.Analysis
	label := fmt.Sprintf("analysis case %q related assessment %q", root.ID, related.ID)
	if child.RecordPin == nil || !child.RecordPin.Same(related.Record) {
		return fmt.Errorf("%s: assessment pin does not identify the nominated record bytes", label)
	}
	if child.Vulnerability.ID != related.Record.RecordID {
		return fmt.Errorf("%s: assessment resolved record %q, not %q",
			label, child.Vulnerability.ID, related.Record.RecordID)
	}
	if child.RequestedID != "" && child.RequestedID != related.Record.RecordID {
		return fmt.Errorf("%s: child requested id %q is not its exact record %q",
			label, child.RequestedID, related.Record.RecordID)
	}
	if child.CorpusDeclaration != nil || child.CorpusManifest != nil {
		return fmt.Errorf("%s: a child candidate may not carry a corpus boundary", label)
	}
	if len(child.Attributions) > 0 {
		return fmt.Errorf("%s: a child candidate may not carry request-level CVE attributions", label)
	}
	if child.RelatedDiscovery != nil || len(child.RelatedRecords) > 0 {
		return fmt.Errorf("%s: a child candidate may not recurse into discovery or further children", label)
	}
	switch disposition {
	case DispositionEvaluated:
		if child.Schema != CaseSchemaV2 || child.RequestedFinding == nil {
			return fmt.Errorf("%s: evaluated candidate was not finalized with an %s requested finding",
				label, CaseSchemaV2)
		}
		if child.RequestedFinding.Status != FindingFinal {
			return fmt.Errorf("%s: evaluated candidate's requested finding is %q, not %q",
				label, child.RequestedFinding.Status, FindingFinal)
		}
		if child.RequestedFinding.PrimaryAssessmentID != child.ID {
			return fmt.Errorf("%s: evaluated candidate requested finding names assessment %q",
				label, child.RequestedFinding.PrimaryAssessmentID)
		}
		childRequestedID, childKind, childCoverage := RequestedIdentity(child)
		if child.RequestedFinding.RequestedID != childRequestedID ||
			child.RequestedFinding.RequestedKind != childKind ||
			child.RequestedFinding.Coverage != childCoverage {
			return fmt.Errorf("%s: evaluated candidate requested finding %q/%s/%q is not its exact-record identity %q/%s/%q",
				label, child.RequestedFinding.RequestedID, child.RequestedFinding.RequestedKind,
				child.RequestedFinding.Coverage, childRequestedID, childKind, childCoverage)
		}
		if !child.RequestedFinding.IsTargetActual {
			return fmt.Errorf("%s: evaluated candidate requested finding is not marked actual", label)
		}
		if len(child.ProfileAssessments) > 0 {
			actual, ok := targetActualProfile(child)
			if !ok {
				return fmt.Errorf("%s: evaluated candidate carries no unique target-actual profile", label)
			}
			if child.RequestedFinding.Profile != actual.Profile {
				return fmt.Errorf("%s: evaluated candidate requested finding profile %q is not its target-actual profile %q",
					label, child.RequestedFinding.Profile, actual.Profile)
			}
		}
	case DispositionUnsupported, DispositionTimedOut, DispositionAmbiguous, DispositionLoadFailed, DispositionNotEvaluated:
		if child.Schema == CaseSchemaV2 {
			return fmt.Errorf("%s: disposition %q child carries a %s envelope; only an evaluated candidate may be finalized",
				label, disposition, CaseSchemaV2)
		}
	default:
		return fmt.Errorf("%s: unknown candidate disposition %q", label, disposition)
	}
	return nil
}

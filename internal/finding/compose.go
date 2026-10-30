// Package finding composes the request-level answer from independently
// assessed records. Composition is positive-only per profile/build: a CVE is
// decided by one admitted-attributed record witness, or by a declared corpus
// negative under Addendum A. It never assembles a witness from different
// records, profiles or builds, and it never rewrites a record's own verdict.
package finding

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Compose projects one analysed request into its authoritative requested
// finding. The case is not mutated. An exact request projects only the primary
// record; related positives stay separate assessments. A CVE request requires
// either one independently earned and admitted-attributed EXPLOITABLE witness
// under the same profile and build, or a complete declared-corpus negative in
// which every nominated candidate is independently NOT_AFFECTED.
func Compose(c *domain.AnalysisCase) (domain.RequestedFinding, error) {
	if c == nil {
		return domain.RequestedFinding{}, fmt.Errorf("compose: nil analysis case")
	}
	requestedID, kind, coverage := domain.RequestedIdentity(c)
	if requestedID == "" {
		return domain.RequestedFinding{}, fmt.Errorf("compose: requested id is required")
	}
	primaryID := c.ID
	if primaryID == "" {
		primaryID = domain.CaseID("assessment")
	}
	actual := actualProfile(c)
	build := domain.EffectiveBuildContext(c.Product)

	embedded, err := composeProfile(c, actual, true, build, kind, requestedID)
	if err != nil {
		return domain.RequestedFinding{}, err
	}
	finding := domain.RequestedFinding{
		Status:              domain.FindingFinal,
		RequestedID:         requestedID,
		RequestedKind:       kind,
		Coverage:            coverage,
		PrimaryAssessmentID: primaryID,
		FindingProfile:      embedded,
	}
	finding.Profiles = append(finding.Profiles, embedded)

	other := domain.ProfileClusterPerimeter
	if actual == domain.ProfileClusterPerimeter {
		other = domain.ProfileZeroTrust
	}
	if _, ok := domain.ProfileAssessmentFor(c, other); ok {
		otherProfile, err := composeProfile(c, other, false, build, kind, requestedID)
		if err != nil {
			return domain.RequestedFinding{}, err
		}
		finding.Profiles = append(finding.Profiles, otherProfile)
	}
	if err := finding.Validate(); err != nil {
		return domain.RequestedFinding{}, fmt.Errorf("compose: %w", err)
	}
	return finding, nil
}

// Finalize assigns the composed requested-finding envelope. It is the only
// writer of RequestedFinding and Schema; composition itself never mutates the
// case's applicability, census, claims, risk or verdict.
func Finalize(c *domain.AnalysisCase) error {
	finding, err := Compose(c)
	if err != nil {
		return err
	}
	c.Schema = domain.CaseSchemaV2
	c.RequestedFinding = &finding
	return nil
}

// actualProfile is the profile the deployment assessment actually selected.
// Task 5 records it on the profile assessments; a case that failed before
// evaluation falls back to the same typed perimeter basis the evaluator uses.
func actualProfile(c *domain.AnalysisCase) domain.ThreatProfile {
	for _, assessment := range c.ProfileAssessments {
		if assessment.IsTargetActual {
			return assessment.Profile
		}
	}
	if c.Product.TrustedPeer ||
		(c.Product.PerimeterOverride != "" && c.Product.PerimeterOverride != "auto") ||
		(c.PerimeterAssessment != nil && c.PerimeterAssessment.AllowsTrustedPeerSelection()) {
		return domain.ProfileClusterPerimeter
	}
	return domain.ProfileZeroTrust
}

func composeProfile(c *domain.AnalysisCase, profile domain.ThreatProfile, actual bool,
	build domain.BuildContext, kind domain.AdvisoryScopeKind, requestedID string) (domain.FindingProfile, error) {
	assessment, hasPrimary := domain.ProfileAssessmentFor(c, profile)
	var buildErr error
	if hasPrimary {
		buildErr = assessment.Build.Matches(build)
	}
	if kind == domain.ScopeAdvisoryEntries {
		if !hasPrimary {
			return failedProfile(c, profile, actual, build, c.AnalysisGaps,
				"the primary record assessment is unavailable"), nil
		}
		if buildErr != nil {
			return failedProfile(c, profile, actual, build,
				append(append([]domain.AnalysisGap(nil), c.AnalysisGaps...), proofArtifactGap(c.ID, buildErr)),
				"the primary record assessment was made under a different build"), nil
		}
		return composeExact(c, assessment, actual, build), nil
	}
	if buildErr != nil {
		// The primary result cannot be composed under this build. Candidate
		// positives may still decide; the mismatch is retained as a diagnostic.
		hasPrimary = false
	}
	return composeCVE(c, assessment, hasPrimary, profile, actual, build, requestedID, buildErr), nil
}

// composeExact projects exactly one record's own result. Related positives are
// never substituted for the primary and remain separate assessments.
func composeExact(c *domain.AnalysisCase, assessment domain.ProfileAssessment, actual bool,
	build domain.BuildContext) domain.FindingProfile {
	finding := findingProfileFromAssessment(assessment, actual)
	finding.Build = build
	if assessment.Result.Outcome != domain.OutcomeDecided ||
		assessment.Result.Verdict == nil ||
		assessment.Result.Verdict.Verdict != domain.VerdictExploitable {
		return finding
	}
	origin, scope, err := buildProofOrigin(c, c, assessment, build, "")
	if err != nil {
		finding = failedProfile(c, assessment.Profile, actual, build,
			append(append([]domain.AnalysisGap(nil), assessment.Result.Gaps...), proofArtifactGap(c.ID, err)),
			"the record earned EXPLOITABLE but its witness could not be published: "+err.Error())
		return finding
	}
	finding.ProofOrigins = []domain.ProofOrigin{origin}
	finding.ExploitabilityScope = scope
	finding.Limitations = appendUniqueStrings(finding.Limitations, domain.ExploitabilityScopeLimitations(scope)...)
	return finding
}

// composeCVE collects independently earned attributed positives first. Only
// when none exists does it attempt the declared-corpus negative route; a
// component negative alone never closes a CVE.
func composeCVE(c *domain.AnalysisCase, assessment domain.ProfileAssessment, hasPrimary bool,
	profile domain.ThreatProfile, actual bool, build domain.BuildContext, requestedID string,
	primaryBuildErr error) domain.FindingProfile {
	comp := collectCVEComposition(c, assessment, hasPrimary, profile, build, requestedID, primaryBuildErr)
	if len(comp.origins) > 0 {
		return composedPositive(comp, actual)
	}
	basis, basisErr := domain.BuildCorpusNegativeBasis(c, profile)
	if basisErr == nil {
		if len(comp.unresolved) == 0 {
			return composedCorpusNegative(c, comp, basis, actual)
		}
		// The corpus itself is complete, but a record-level positive or its
		// attribution remains unresolved and could change the answer.
		basisErr = fmt.Errorf("a record-level positive or attribution remains unresolved beside the declared corpus")
	}
	if len(comp.unresolved) == 0 && !comp.blocked && len(comp.externalDeps) > 0 {
		if _, boundaryErr := domain.DeclaredCorpusBoundary(c); boundaryErr == nil {
			return composedExternal(comp, actual)
		}
	}
	return composedFailed(c, comp, actual, build, basisErr)
}

// profileComposition is the per-profile evidence collected from the primary and
// related records. Origins only ever contain independently earned positive
// witnesses from this profile and build.
type profileComposition struct {
	profile      domain.ThreatProfile
	build        domain.BuildContext
	origins      []domain.ProofOrigin
	scopes       []domain.ExploitabilityScope
	unresolved   []domain.AnalysisGap
	diagnostics  []domain.AnalysisGap
	externalDeps []domain.ExternalDependency
	externalGaps []domain.AnalysisGap
	limitations  []string
	blocked      bool
}

func collectCVEComposition(c *domain.AnalysisCase, assessment domain.ProfileAssessment, hasPrimary bool,
	profile domain.ThreatProfile, build domain.BuildContext, requestedID string,
	primaryBuildErr error) profileComposition {
	comp := profileComposition{profile: profile, build: build}
	if primaryBuildErr != nil {
		comp.limitations = append(comp.limitations,
			"the primary record assessment was made under a different build and was not composed: "+primaryBuildErr.Error())
	}
	if hasPrimary {
		comp.addRecord(c, c, assessment, requestedID)
	} else if c.Vulnerability.ID == "" {
		comp.limitations = append(comp.limitations,
			"the primary record could not be resolved; the declared corpus still bounds the implementations examined")
		for _, gap := range c.AnalysisGaps {
			if gap.Owner == domain.GapOwnerExternal {
				comp.externalGaps = append(comp.externalGaps, gap)
				continue
			}
			comp.diagnostics = append(comp.diagnostics, gap)
		}
	} else {
		comp.limitations = append(comp.limitations,
			"the primary record was resolved but its assessment did not complete; its diagnostics are retained")
		for _, gap := range c.AnalysisGaps {
			if gap.Owner == domain.GapOwnerExternal {
				comp.externalGaps = append(comp.externalGaps, gap)
				continue
			}
			comp.diagnostics = append(comp.diagnostics, gap)
		}
	}
	// Only an evaluated candidate may contribute. A child case retained for
	// diagnostics (load failure, timeout, unsupported runner) must never lift
	// a positive merely because its partial assessment recorded one.
	evaluated := map[domain.RecordPin]bool{}
	if c.RelatedDiscovery != nil {
		for _, candidate := range c.RelatedDiscovery.Candidates {
			if candidate.Disposition == domain.DispositionEvaluated {
				evaluated[candidate.Record] = true
			}
		}
	}
	for _, related := range c.RelatedRecords {
		if c.RelatedDiscovery != nil && !evaluated[related.Record] {
			comp.blocked = true
			comp.unresolved = append(comp.unresolved, proofArtifactGap(c.ID,
				fmt.Errorf("candidate %q (%s) is not in an evaluated disposition",
					related.Record.RecordID, related.Record.DocumentDigest)))
			continue
		}
		child := related.Analysis
		if child == nil {
			comp.blocked = true
			comp.unresolved = append(comp.unresolved, proofArtifactGap(c.ID,
				fmt.Errorf("candidate %q carries no independent assessment", related.Record.RecordID)))
			continue
		}
		childAssessment, ok := domain.ProfileAssessmentFor(child, profile)
		if !ok {
			comp.blocked = true
			comp.unresolved = append(comp.unresolved, proofArtifactGap(c.ID,
				fmt.Errorf("candidate %q has no %q profile assessment", child.Vulnerability.ID, profile)))
			continue
		}
		comp.addRecord(child, c, childAssessment, requestedID)
	}
	return comp
}

// addRecord contributes one record's result to the composition. A positive
// needs its own pin, its own admitted attribution and its own evidence; a
// failure blocks closure; an external result is retained as a genuine external
// dependency unless analyzer work remains.
func (comp *profileComposition) addRecord(recordCase, request *domain.AnalysisCase,
	assessment domain.ProfileAssessment, requestedID string) {
	recordID := recordCase.Vulnerability.ID
	result := assessment.Result
	switch result.Outcome {
	case domain.OutcomeDecided:
		if result.Verdict == nil {
			comp.blocked = true
			comp.unresolved = append(comp.unresolved, proofArtifactGap(recordCase.ID,
				fmt.Errorf("record %q decided without a verdict", recordID)))
			return
		}
		if result.Verdict.Verdict != domain.VerdictExploitable {
			return
		}
		if err := assessment.Build.Matches(comp.build); err != nil {
			comp.blocked = true
			scopeErr := fmt.Errorf("record %q earned EXPLOITABLE only under a different build: %w", recordID, err)
			comp.unresolved = append(comp.unresolved, scopeGap(recordCase.ID, scopeErr))
			return
		}
		attribution := admittedAttributionFor(request, recordCase.RecordPin, requestedID)
		if attribution == nil {
			comp.blocked = true
			comp.unresolved = append(comp.unresolved, attributionGap(recordCase.ID,
				fmt.Errorf("record %q is independently EXPLOITABLE but no admitted attribution to %s exists",
					recordID, requestedID)))
			return
		}
		origin, scope, err := buildProofOrigin(recordCase, request, assessment, comp.build, attribution.ID)
		if err != nil {
			comp.blocked = true
			comp.unresolved = append(comp.unresolved, proofArtifactGap(recordCase.ID,
				fmt.Errorf("record %q positive witness: %w", recordID, err)))
			return
		}
		comp.origins = append(comp.origins, origin)
		comp.scopes = append(comp.scopes, scope)
	case domain.OutcomeExternal:
		comp.externalDeps = append(comp.externalDeps, result.ExternalDependencies...)
		comp.externalGaps = append(comp.externalGaps, result.Gaps...)
		comp.limitations = append(comp.limitations,
			fmt.Sprintf("record %q has unresolved external dependencies", recordID))
	default: // OutcomeFailed
		comp.blocked = true
		for _, gap := range result.Gaps {
			if gap.Owner == domain.GapOwnerExternal {
				comp.externalGaps = append(comp.externalGaps, gap)
				continue
			}
			comp.diagnostics = append(comp.diagnostics, gap)
		}
	}
}

func composedPositive(comp profileComposition, actual bool) domain.FindingProfile {
	scope := comp.scopes[0]
	origins := make([]domain.ProofOrigin, 0, len(comp.origins))
	for i, origin := range comp.origins {
		if comp.scopes[i] == scope {
			origins = append(origins, origin)
		}
	}
	finding := domain.FindingProfile{
		Profile:             comp.profile,
		IsTargetActual:      actual,
		Build:               comp.build,
		Outcome:             domain.OutcomeDecided,
		Verdict:             domain.VerdictExploitable,
		Reason:              "an independently assessed and attributed record earned the requested positive",
		ExploitabilityScope: scope,
		ProofOrigins:        origins,
	}
	finding.Limitations = append(finding.Limitations, domain.ExploitabilityScopeLimitations(scope)...)
	finding.Gaps = append(finding.Gaps, comp.diagnostics...)
	for _, gap := range comp.unresolved {
		finding.Limitations = append(finding.Limitations,
			"unresolved candidate diagnostic not needed for the decided answer: "+gap.Message)
	}
	for _, gap := range comp.externalGaps {
		finding.Limitations = append(finding.Limitations,
			"external dependency of a non-deciding record: "+gap.Message)
	}
	finding.Limitations = append(finding.Limitations, comp.limitations...)
	return finding
}

func composedCorpusNegative(c *domain.AnalysisCase, comp profileComposition,
	basis *domain.CorpusNegativeBasis, actual bool) domain.FindingProfile {
	finding := domain.FindingProfile{
		Profile:             comp.profile,
		IsTargetActual:      actual,
		Build:               comp.build,
		Outcome:             domain.OutcomeDecided,
		Verdict:             domain.VerdictNotAffected,
		Reason:              "every nominated implementation in the declared corpus is independently not affected",
		CorpusNegativeBasis: basis,
		Limitations:         []string{basis.BoundaryStatement},
	}
	if c.RelatedDiscovery != nil {
		finding.Limitations = append(finding.Limitations, c.RelatedDiscovery.Limitations...)
	}
	finding.Limitations = append(finding.Limitations, c.EvidenceGraph.Limitations...)
	for _, gap := range comp.diagnostics {
		finding.Limitations = append(finding.Limitations,
			"independent record diagnostic not needed for the corpus negative: "+gap.Message)
	}
	for _, gap := range comp.externalGaps {
		finding.Limitations = append(finding.Limitations,
			"external dependency of a not-affected record: "+gap.Message)
	}
	finding.Limitations = append(finding.Limitations, comp.limitations...)
	return finding
}

func composedExternal(comp profileComposition, actual bool) domain.FindingProfile {
	dependencies := dedupeDependencies(comp.externalDeps)
	finding := domain.FindingProfile{
		Profile:              comp.profile,
		IsTargetActual:       actual,
		Build:                comp.build,
		Outcome:              domain.OutcomeExternal,
		Verdict:              domain.VerdictInconclusive,
		Reason:               "the request depends on external facts that the artifact and selected profile cannot settle",
		ExternalDependencies: dependencies,
		Gaps:                 append([]domain.AnalysisGap(nil), comp.externalGaps...),
		Limitations:          append([]string(nil), comp.limitations...),
	}
	for _, gap := range comp.diagnostics {
		finding.Limitations = append(finding.Limitations,
			"request diagnostic retained beside the external dependency: "+gap.Message)
	}
	return finding
}

func composedFailed(c *domain.AnalysisCase, comp profileComposition, actual bool,
	build domain.BuildContext, cause error) domain.FindingProfile {
	gaps := []domain.AnalysisGap{scopeGap(caseID(c), cause)}
	gaps = append(gaps, comp.unresolved...)
	gaps = append(gaps, comp.diagnostics...)
	gaps = append(gaps, comp.externalGaps...)
	reason := "no positive was independently earned and the declared corpus cannot close the CVE request"
	if len(comp.unresolved) > 0 {
		reason = "an independently positive record could not be attributed or its witness could not be published"
	}
	finding := failedProfile(c, comp.profile, actual, build, gaps, reason)
	finding.Limitations = append(finding.Limitations, comp.limitations...)
	return finding
}

func failedProfile(c *domain.AnalysisCase, profile domain.ThreatProfile, actual bool,
	build domain.BuildContext, gaps []domain.AnalysisGap, reason string) domain.FindingProfile {
	gaps = append([]domain.AnalysisGap(nil), gaps...)
	id := caseID(c)
	for i := range gaps {
		if gaps[i].AssessmentID == "" {
			gaps[i].AssessmentID = id
		}
	}
	if len(gaps) == 0 {
		gaps = append(gaps, domain.AnalysisGap{
			Owner:        domain.GapOwnerCode,
			Code:         domain.GapUnclassifiedAnalysisGap,
			Obligation:   domain.ObligationMeasurement,
			AssessmentID: id,
			Message:      reason,
		})
	}
	finding := domain.FindingProfile{
		Profile:        profile,
		IsTargetActual: actual,
		Build:          build,
		Outcome:        domain.OutcomeFailed,
		Reason:         reason,
		Gaps:           gaps,
	}
	if c != nil {
		finding.Limitations = append(finding.Limitations, c.EvidenceGraph.Limitations...)
	}
	return finding
}

func findingProfileFromAssessment(assessment domain.ProfileAssessment, actual bool) domain.FindingProfile {
	result := assessment.Result
	finding := domain.FindingProfile{
		Profile:              assessment.Profile,
		IsTargetActual:       actual,
		Build:                assessment.Build,
		Outcome:              result.Outcome,
		Verdict:              verdictOfResult(result),
		Reason:               assessmentReason(result),
		ExternalDependencies: append([]domain.ExternalDependency(nil), result.ExternalDependencies...),
		Gaps:                 append([]domain.AnalysisGap(nil), result.Gaps...),
		Limitations:          append([]string(nil), result.Limitations...),
	}
	if result.Verdict != nil {
		finding.ExploitabilityScope = result.Verdict.ExploitabilityScope
		finding.Limitations = appendUniqueStrings(finding.Limitations,
			domain.ExploitabilityScopeLimitations(result.Verdict.ExploitabilityScope)...)
	}
	return finding
}

// buildProofOrigin derives one publication-grade witness from a record's own
// assessment: its pin, the verdict's conditions, the claims and evidence those
// conditions cite, and the record's own affected entry/mechanism binding.
func buildProofOrigin(recordCase, request *domain.AnalysisCase, assessment domain.ProfileAssessment,
	build domain.BuildContext, attributionID string) (domain.ProofOrigin, domain.ExploitabilityScope, error) {
	if recordCase == nil || recordCase.RecordPin == nil {
		return domain.ProofOrigin{}, "", fmt.Errorf("the positive record carries no exact document pin")
	}
	verdict := assessment.Result.Verdict
	if verdict == nil || verdict.Verdict != domain.VerdictExploitable {
		return domain.ProofOrigin{}, "", fmt.Errorf("the record assessment is not EXPLOITABLE")
	}
	if err := assessment.Build.Matches(build); err != nil {
		return domain.ProofOrigin{}, "", err
	}
	origin := domain.ProofOrigin{
		AssessmentID:  recordCase.ID,
		Record:        *recordCase.RecordPin,
		AttributionID: attributionID,
		Profile:       assessment.Profile,
		Build:         assessment.Build,
	}
	for _, id := range verdict.ConditionIDs {
		origin.ConditionRefs = append(origin.ConditionRefs, domain.QualifiedRef{AssessmentID: recordCase.ID, Ref: string(id)})
	}
	if len(origin.ConditionRefs) == 0 {
		return domain.ProofOrigin{}, "", fmt.Errorf("the positive verdict cites no condition")
	}
	conditions := make(map[domain.ConditionID]bool, len(verdict.ConditionIDs))
	for _, id := range verdict.ConditionIDs {
		conditions[id] = true
	}
	evidence := make(map[domain.EvidenceID]bool, len(verdict.EvidenceIDs)+4)
	for _, id := range verdict.EvidenceIDs {
		evidence[id] = true
	}
	for _, claim := range recordCase.Claims {
		if !conditions[claim.ConditionID] {
			continue
		}
		origin.ClaimRefs = append(origin.ClaimRefs, domain.QualifiedRef{AssessmentID: recordCase.ID, Ref: string(claim.ID)})
		for _, id := range claim.EvidenceIDs {
			evidence[id] = true
		}
		if claim.NegativeVerification != nil {
			for _, id := range claim.NegativeVerification.EvidenceIDs {
				evidence[id] = true
			}
		}
	}
	for id := range evidence {
		origin.EvidenceRefs = append(origin.EvidenceRefs, domain.QualifiedRef{AssessmentID: recordCase.ID, Ref: string(id)})
	}
	sort.Slice(origin.EvidenceRefs, func(i, j int) bool { return origin.EvidenceRefs[i].Ref < origin.EvidenceRefs[j].Ref })
	if len(origin.EvidenceRefs) == 0 {
		return domain.ProofOrigin{}, "", fmt.Errorf("the positive verdict cites no evidence")
	}
	origin.EntryRefs, origin.MechanismID = originBinding(recordCase, attributionForPin(request, recordCase.RecordPin, attributionID))
	if err := origin.Validate(); err != nil {
		return domain.ProofOrigin{}, "", err
	}
	return origin, verdict.ExploitabilityScope, nil
}

// originBinding selects the affected entry and mechanism the witness covers.
// A rooted transport witness is the strongest binding; an admitted attribution
// binds the implementation; the record's own represented inventory is the
// fallback.
func originBinding(c *domain.AnalysisCase, attribution *domain.CVEAttribution) ([]int, string) {
	input, trigger := domain.TransportWitnessFromEvidence(c.EvidenceGraph.EvidenceList())
	var entries []int
	if input != nil && len(input.EntryRefs) > 0 {
		entries = append(entries, input.EntryRefs...)
	}
	if len(entries) == 0 && attribution != nil {
		entries = append(entries, attribution.EntryRefs...)
	}
	if len(entries) == 0 && c.Vulnerability.Scope != nil && c.Vulnerability.Scope.RecordInventory != nil {
		entries = append(entries, c.Vulnerability.Scope.RecordInventory.RepresentedRefs...)
	}
	entries = normalizedEntryRefs(entries)

	mechanism := ""
	if trigger != nil && trigger.Mechanism != "" {
		mechanism = trigger.Mechanism
	} else if input != nil && input.Mechanism != "" {
		mechanism = input.Mechanism
	} else if attribution != nil && attribution.MechanismID != "" {
		mechanism = attribution.MechanismID
	} else if c.Exploit != nil {
		conditions := append(append([]domain.Condition(nil), c.Exploit.MandatoryConditions...), c.Exploit.SupportingFactors...)
		for _, condition := range conditions {
			if value := condition.Params[domain.ParamMechanism]; value != "" {
				mechanism = value
				break
			}
		}
	}
	return entries, mechanism
}

func normalizedEntryRefs(refs []int) []int {
	if len(refs) == 0 {
		return nil
	}
	sorted := append([]int(nil), refs...)
	sort.Ints(sorted)
	out := sorted[:1]
	for _, ref := range sorted[1:] {
		if ref != out[len(out)-1] {
			out = append(out, ref)
		}
	}
	return out
}

func admittedAttributionFor(c *domain.AnalysisCase, pin *domain.RecordPin, requestedID string) *domain.CVEAttribution {
	if c == nil || pin == nil {
		return nil
	}
	for i := range c.Attributions {
		attribution := &c.Attributions[i]
		if attribution.Admitted() &&
			attribution.Candidate.Same(*pin) &&
			strings.EqualFold(attribution.CVEID, requestedID) {
			return attribution
		}
	}
	return nil
}

func attributionForPin(c *domain.AnalysisCase, pin *domain.RecordPin, attributionID string) *domain.CVEAttribution {
	if c == nil || pin == nil {
		return nil
	}
	for i := range c.Attributions {
		attribution := &c.Attributions[i]
		if !attribution.Admitted() || !attribution.Candidate.Same(*pin) {
			continue
		}
		if attributionID != "" && attribution.ID != attributionID {
			continue
		}
		return attribution
	}
	return nil
}

func scopeGap(id domain.CaseID, cause error) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:        domain.GapOwnerScope,
		Code:         domain.GapUnsupportedNegativeScope,
		Obligation:   domain.ObligationNegativeScope,
		AssessmentID: id,
		Message:      cause.Error(),
	}
}

func attributionGap(id domain.CaseID, cause error) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:        domain.GapOwnerCode,
		Code:         domain.GapCVEAttributionUnresolved,
		Obligation:   domain.ObligationAttribution,
		AssessmentID: id,
		Message:      cause.Error(),
	}
}

func proofArtifactGap(id domain.CaseID, cause error) domain.AnalysisGap {
	return domain.AnalysisGap{
		Owner:        domain.GapOwnerProof,
		Code:         domain.GapProofArtifactMissing,
		Obligation:   domain.ObligationCondition,
		AssessmentID: id,
		Message:      cause.Error(),
	}
}

func verdictOfResult(result domain.AssessmentResult) domain.Verdict {
	if result.Verdict == nil {
		return ""
	}
	return result.Verdict.Verdict
}

func assessmentReason(result domain.AssessmentResult) string {
	if result.Verdict != nil {
		return result.Verdict.Reason
	}
	parts := make([]string, 0, len(result.Gaps))
	for _, gap := range result.Gaps {
		parts = append(parts, string(gap.Code)+": "+gap.Message)
	}
	if len(parts) == 0 {
		return "analysis FAILED without a typed cause"
	}
	return "analysis FAILED: " + strings.Join(parts, "; ")
}

func caseID(c *domain.AnalysisCase) domain.CaseID {
	if c != nil && c.ID != "" {
		return c.ID
	}
	return domain.CaseID("assessment")
}

func dedupeDependencies(dependencies []domain.ExternalDependency) []domain.ExternalDependency {
	seen := make(map[string]bool, len(dependencies))
	out := make([]domain.ExternalDependency, 0, len(dependencies))
	for _, dependency := range dependencies {
		key := string(dependency.AffectedObligation) + "\x00" + dependency.MissingFact
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dependency)
	}
	return out
}

func appendUniqueStrings(dst []string, values ...string) []string {
	for _, value := range values {
		if value == "" {
			continue
		}
		if !containsString(dst, value) {
			dst = append(dst, value)
		}
	}
	return dst
}

func containsString(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

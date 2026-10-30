package domain

import (
	"fmt"
	"slices"
	"strings"
)

// AssessmentOutcome is the terminal classification of one assessment. It is a
// proposition about the analysis itself, disjoint from Verdict: FAILED is not
// a fifth vulnerability verdict, it means no verdict was earned. Claim truth
// values are unchanged by this classification — a failed measurement still
// leaves its claim UNKNOWN.
//
//	DECIDED              an admitted proof earned the exact requested answer;
//	                     the assessment carries one of the three definitive
//	                     verdicts.
//	EXTERNAL_DEPENDENCY  a named, evidence-bound, decision-changing fact lies
//	                     outside the artifact and the selected threat profile;
//	                     the assessment carries INCONCLUSIVE.
//	FAILED               analysis, input resolution, proof capability or scope
//	                     authority was insufficient; no verdict is published.
//	                     An unfinished code analysis is not a legitimate
//	                     INCONCLUSIVE answer.
type AssessmentOutcome string

const (
	OutcomeDecided  AssessmentOutcome = "DECIDED"
	OutcomeExternal AssessmentOutcome = "EXTERNAL_DEPENDENCY"
	OutcomeFailed   AssessmentOutcome = "FAILED"
)

// Valid reports whether the outcome is one of the three frozen terminal
// classifications.
func (o AssessmentOutcome) Valid() bool {
	switch o {
	case OutcomeDecided, OutcomeExternal, OutcomeFailed:
		return true
	default:
		return false
	}
}

// FindingStatus is the persistence phase of a RequestedFinding envelope.
// PENDING is a phase, not a fourth assessment outcome: a pending envelope has
// not claimed an outcome yet, so it carries no outcome and no verdict.
type FindingStatus string

const (
	FindingPending FindingStatus = "PENDING"
	FindingFinal   FindingStatus = "FINAL"
)

// Valid reports whether the status is one of the two frozen persistence
// phases.
func (s FindingStatus) Valid() bool {
	switch s {
	case FindingPending, FindingFinal:
		return true
	default:
		return false
	}
}

// CaseResultSchema discriminates the persisted case result contract. The zero
// value marks a legacy case written before analysis-case/2; a legacy case is
// readable but must not acquire inferred outcome, discovery or corpus data.
type CaseResultSchema string

// CaseSchemaV2 is the result schema that always carries a requested-finding
// envelope, record pins, profile assessments and structured analysis gaps.
const CaseSchemaV2 CaseResultSchema = "analysis-case/2"

// Valid reports whether the schema is the frozen v2 discriminator. Callers
// testing legacy cases compare against the zero value instead.
func (s CaseResultSchema) Valid() bool { return s == CaseSchemaV2 }

// QualifiedRef binds one reference to the assessment that produced it.
// Unqualified identifiers are ambiguous in a composed request result because
// every candidate record owns its own evidence, condition and claim ids, so a
// bare id may not be published.
type QualifiedRef struct {
	AssessmentID CaseID `json:"assessment_id"`
	Ref          string `json:"ref"`
}

// Validate rejects an unbound reference: without an owning assessment the
// reference cannot be re-admitted on replay.
func (r QualifiedRef) Validate() error {
	if r.AssessmentID == "" {
		return fmt.Errorf("qualified ref %q: assessment id is required", r.Ref)
	}
	if strings.TrimSpace(r.Ref) == "" {
		return fmt.Errorf("qualified ref for assessment %q: ref is required", r.AssessmentID)
	}
	return nil
}

func validateQualifiedRefs(name string, refs []QualifiedRef) error {
	for n, ref := range refs {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, n, err)
		}
	}
	return nil
}

// validateEntryRefs enforces ordered, deduplicated original affected[] entry
// indices. Requiring the order makes the duplicate check allocation-free and
// matches the census convention the record inventory already uses.
func validateEntryRefs(name string, refs []int) error {
	for n, ref := range refs {
		if ref < 0 {
			return fmt.Errorf("%s[%d]=%d is negative", name, n, ref)
		}
		if n > 0 && ref <= refs[n-1] {
			return fmt.Errorf("%s is not strictly ordered at position %d (%d after %d)", name, n, ref, refs[n-1])
		}
	}
	return nil
}

// validatePinnedDigest checks the sha256:<lowercase hex> form every record pin
// and corpus digest uses. Documents are pinned by their raw-byte SHA-256 so a
// later read can prove it re-read the same bytes.
func validatePinnedDigest(name, digest string) error {
	if !strings.HasPrefix(digest, recordDigestPrefix) {
		return fmt.Errorf("%s %q is not a %ssha256 digest", name, digest, recordDigestPrefix)
	}
	if !hexDigestSha256.MatchString(digest[len(recordDigestPrefix):]) {
		return fmt.Errorf("%s %q is not a lowercase 64-hex sha256 digest", name, digest)
	}
	return nil
}

// RecordPin identifies the exact document bytes one assessment was derived
// from. RecordID is the record's own id; DocumentDigest pins the raw bytes;
// SourceLocator records where those bytes were read from. A pin is the only
// admissible evidence that an assessment used its own record.
type RecordPin struct {
	RecordID       string `json:"record_id"`
	DocumentDigest string `json:"document_digest"`
	SourceLocator  string `json:"source_locator"`
	Modified       string `json:"modified,omitempty"`
}

// Validate enforces the closed pin record used to re-read exact bytes.
func (p RecordPin) Validate() error {
	if strings.TrimSpace(p.RecordID) == "" {
		return fmt.Errorf("record pin: record id is required")
	}
	if strings.TrimSpace(p.SourceLocator) == "" {
		return fmt.Errorf("record pin %q: source locator is required", p.RecordID)
	}
	if err := validatePinnedDigest("record pin "+p.RecordID+" document digest", p.DocumentDigest); err != nil {
		return err
	}
	return nil
}

// Same reports whether two pins identify the same document bytes. The source
// locator is deliberately excluded: the same bytes supplied through a second
// configured locator are the same record document.
func (p RecordPin) Same(other RecordPin) bool {
	return p.RecordID == other.RecordID && p.DocumentDigest == other.DocumentDigest
}

// Obligation is the controlled identifier of the proof obligation a gap or an
// external dependency concerns. It is a closed enum, never prose to parse: a
// consumer routes on the identifier, and a human explanation travels in the
// gap message instead.
type Obligation string

const (
	// Affected-chain axes. Each is artifact-owned for an identified build.
	ObligationModuleMembership       Obligation = "MODULE_MEMBERSHIP"
	ObligationVersionRange           Obligation = "VERSION_RANGE"
	ObligationPackagePresence        Obligation = "PACKAGE_PRESENCE"
	ObligationBuildInclusion         Obligation = "BUILD_INCLUSION"
	ObligationImplementationPresence Obligation = "IMPLEMENTATION_PRESENCE"
	// ObligationRootCause is the defect locus / root-cause model.
	ObligationRootCause Obligation = "ROOT_CAUSE"
	// ObligationCondition is one mandatory exploit condition of the
	// conjunction, including transport/trigger conditions.
	ObligationCondition Obligation = "MANDATORY_CONDITION"
	// Request-level capabilities.
	ObligationDiscovery     Obligation = "DISCOVERY"
	ObligationAttribution   Obligation = "ATTRIBUTION"
	ObligationMeasurement   Obligation = "MEASUREMENT"
	ObligationNegativeScope Obligation = "NEGATIVE_SCOPE"
)

// Validate rejects an unknown obligation identifier.
func (o Obligation) Validate() error {
	switch o {
	case ObligationModuleMembership, ObligationVersionRange, ObligationPackagePresence,
		ObligationBuildInclusion, ObligationImplementationPresence, ObligationRootCause,
		ObligationCondition, ObligationDiscovery, ObligationAttribution,
		ObligationMeasurement, ObligationNegativeScope:
		return nil
	default:
		return fmt.Errorf("unknown obligation %q", o)
	}
}

// GapOwner classifies who must discharge an analysis gap. Only EXTERNAL may
// carry an external dependency: an LLM cannot make a gap environmental merely
// by labelling it, and "inspect more code" is never EXTERNAL.
type GapOwner string

const (
	GapOwnerCode     GapOwner = "CODE"     // code/source analysis work remains
	GapOwnerProof    GapOwner = "PROOF"    // proof capability or verification remains
	GapOwnerInput    GapOwner = "INPUT"    // a required input could not be resolved
	GapOwnerScope    GapOwner = "SCOPE"    // scope authority is insufficient
	GapOwnerExternal GapOwner = "EXTERNAL" // a fact outside the artifact decides
)

// Validate rejects an unknown gap owner.
func (o GapOwner) Validate() error {
	switch o {
	case GapOwnerCode, GapOwnerProof, GapOwnerInput, GapOwnerScope, GapOwnerExternal:
		return nil
	default:
		return fmt.Errorf("unknown gap owner %q", o)
	}
}

// GapCode is the typed cause a producer emits when it cannot discharge an
// obligation. Outcome classification routes on these codes, never on
// limitation or error text.
type GapCode string

const (
	GapAnalysisBudgetExhausted        GapCode = "ANALYSIS_BUDGET_EXHAUSTED"
	GapAnalysisTimeout                GapCode = "ANALYSIS_TIMEOUT"
	GapInputResolutionFailed          GapCode = "INPUT_RESOLUTION_FAILED"
	GapMeasurementNotCompleted        GapCode = "MEASUREMENT_NOT_COMPLETED"
	GapRootCauseUnresolved            GapCode = "ROOT_CAUSE_UNRESOLVED"
	GapReachabilityProofIncomplete    GapCode = "REACHABILITY_PROOF_INCOMPLETE"
	GapInputTraceIncomplete           GapCode = "INPUT_TRACE_INCOMPLETE"
	GapTriggerProofIncomplete         GapCode = "TRIGGER_PROOF_INCOMPLETE"
	GapNegativeVerificationIncomplete GapCode = "NEGATIVE_VERIFICATION_INCOMPLETE"
	GapReviewUnresolved               GapCode = "REVIEW_UNRESOLVED"
	GapProofArtifactMissing           GapCode = "PROOF_ARTIFACT_MISSING"
	GapUnsupportedNegativeScope       GapCode = "UNSUPPORTED_NEGATIVE_SCOPE"
	GapCVEAttributionUnresolved       GapCode = "CVE_ATTRIBUTION_UNRESOLVED"
	GapDiscoveryUnavailable           GapCode = "DISCOVERY_UNAVAILABLE"
	// GapExternalDependencyUnresolved is the only code an EXTERNAL-owned gap may
	// carry: the discriminating detail lives in its external dependency, and an
	// analyzer-owned code must never label an external fact.
	GapExternalDependencyUnresolved GapCode = "EXTERNAL_DEPENDENCY_UNRESOLVED"
	// GapUnclassifiedAnalysisGap is the terminalization fallback: unresolved
	// blockers that no producer classified still fail the assessment rather
	// than abstaining.
	GapUnclassifiedAnalysisGap GapCode = "UNCLASSIFIED_ANALYSIS_GAP"
)

// Validate rejects an unknown gap code.
func (c GapCode) Validate() error {
	switch c {
	case GapAnalysisBudgetExhausted, GapAnalysisTimeout, GapInputResolutionFailed,
		GapMeasurementNotCompleted, GapRootCauseUnresolved, GapReachabilityProofIncomplete,
		GapInputTraceIncomplete, GapTriggerProofIncomplete, GapNegativeVerificationIncomplete,
		GapReviewUnresolved, GapProofArtifactMissing, GapUnsupportedNegativeScope,
		GapCVEAttributionUnresolved, GapDiscoveryUnavailable, GapExternalDependencyUnresolved,
		GapUnclassifiedAnalysisGap:
		return nil
	default:
		return fmt.Errorf("unknown gap code %q", c)
	}
}

// ExternalDependency is the complete record of one decision-changing fact that
// lies outside the artifact and the selected threat profile. Every field is
// mandatory: an external-dependency result must locate the boundary in
// evidence, explain why the artifact cannot supply the fact, and name what
// would resolve it. Holding the artifact and profile fixed, two legitimate
// environments must be able to produce different answers — otherwise the gap
// is analyzer work, not externality.
type ExternalDependency struct {
	MissingFact             string         `json:"missing_fact"`
	AffectedObligation      Obligation     `json:"affected_obligation"`
	BoundaryEvidenceRefs    []QualifiedRef `json:"boundary_evidence_refs"`
	WhyArtifactCannotSupply string         `json:"why_artifact_cannot_supply"`
	AlternativesChanging    []string       `json:"alternatives_changing_answer"`
	ResolvingEvidence       string         `json:"resolving_evidence"`
}

// Validate enforces the evidence-bound external-dependency record. A partially
// specified dependency is not an admissible external answer.
func (d ExternalDependency) Validate() error {
	if strings.TrimSpace(d.MissingFact) == "" {
		return fmt.Errorf("external dependency: missing fact is required")
	}
	if err := d.AffectedObligation.Validate(); err != nil {
		return fmt.Errorf("external dependency %q: %w", d.MissingFact, err)
	}
	if len(d.BoundaryEvidenceRefs) == 0 {
		return fmt.Errorf("external dependency %q: at least one boundary evidence reference is required", d.MissingFact)
	}
	if err := validateQualifiedRefs("external dependency "+d.MissingFact+" boundary evidence", d.BoundaryEvidenceRefs); err != nil {
		return err
	}
	if strings.TrimSpace(d.WhyArtifactCannotSupply) == "" {
		return fmt.Errorf("external dependency %q: why the artifact cannot supply the fact is required", d.MissingFact)
	}
	if len(d.AlternativesChanging) == 0 {
		return fmt.Errorf("external dependency %q: at least one answer-changing alternative is required", d.MissingFact)
	}
	for n, alternative := range d.AlternativesChanging {
		if strings.TrimSpace(alternative) == "" {
			return fmt.Errorf("external dependency %q: alternatives_changing_answer[%d] is empty", d.MissingFact, n)
		}
	}
	if strings.TrimSpace(d.ResolvingEvidence) == "" {
		return fmt.Errorf("external dependency %q: resolving evidence is required", d.MissingFact)
	}
	return nil
}

// AnalysisGap is one typed, structured cause a producer records when it cannot
// discharge an obligation. External gaps carry the evidence-bound dependency
// inline; every other owner must not, so an analyzer-owned blocker can never be
// published as an environmental question.
type AnalysisGap struct {
	Owner        GapOwner            `json:"owner"`
	Code         GapCode             `json:"code"`
	Obligation   Obligation          `json:"obligation"`
	AssessmentID CaseID              `json:"assessment_id"`
	ConditionID  ConditionID         `json:"condition_id,omitempty"`
	EvidenceRefs []QualifiedRef      `json:"evidence_refs,omitempty"`
	Message      string              `json:"message"`
	External     *ExternalDependency `json:"external_dependency,omitempty"`
}

// Validate enforces the typed gap record and its owner/dependency coupling.
func (g AnalysisGap) Validate() error {
	if err := g.Owner.Validate(); err != nil {
		return fmt.Errorf("analysis gap: %w", err)
	}
	if err := g.Code.Validate(); err != nil {
		return fmt.Errorf("analysis gap (%s): %w", g.Owner, err)
	}
	if err := g.Obligation.Validate(); err != nil {
		return fmt.Errorf("analysis gap (%s/%s): %w", g.Owner, g.Code, err)
	}
	if g.AssessmentID == "" {
		return fmt.Errorf("analysis gap (%s/%s): assessment id is required", g.Owner, g.Code)
	}
	if strings.TrimSpace(g.Message) == "" {
		return fmt.Errorf("analysis gap (%s/%s) of assessment %q: message is required", g.Owner, g.Code, g.AssessmentID)
	}
	if err := validateQualifiedRefs("analysis gap ("+string(g.Owner)+"/"+string(g.Code)+") evidence", g.EvidenceRefs); err != nil {
		return err
	}
	if g.Owner == GapOwnerExternal {
		if g.Code != GapExternalDependencyUnresolved {
			return fmt.Errorf("analysis gap: EXTERNAL owner must carry %s, got %s",
				GapExternalDependencyUnresolved, g.Code)
		}
		if g.External == nil {
			return fmt.Errorf("analysis gap (%s/%s): EXTERNAL owner requires an external dependency", g.Owner, g.Code)
		}
		if err := g.External.Validate(); err != nil {
			return fmt.Errorf("analysis gap (%s/%s): %w", g.Owner, g.Code, err)
		}
		return nil
	}
	if g.External != nil {
		return fmt.Errorf("analysis gap (%s/%s): only the EXTERNAL owner may carry an external dependency", g.Owner, g.Code)
	}
	return nil
}

func validateAnalysisGaps(name string, gaps []AnalysisGap) error {
	for n, gap := range gaps {
		if err := gap.Validate(); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, n, err)
		}
	}
	return nil
}

// definitiveVerdict reports whether v is one of the three verdicts an earned
// proof may publish. INCONCLUSIVE is never definitive: it is the public
// projection of EXTERNAL_DEPENDENCY only.
func definitiveVerdict(v Verdict) bool {
	switch v {
	case VerdictExploitable, VerdictNotAffected, VerdictNoExploitPathFound:
		return true
	default:
		return false
	}
}

func knownVerdict(v Verdict) bool {
	return v == VerdictInconclusive || definitiveVerdict(v)
}

// AssessmentResult is the terminal result of one assessment, including the
// primary. Outcome is authoritative; Verdict is the record-level public verdict
// and is absent for FAILED.
type AssessmentResult struct {
	Outcome AssessmentOutcome `json:"assessment_outcome"`
	// Verdict is the public verdict this assessment earned. DECIDED requires
	// one of the three definitive verdicts; EXTERNAL_DEPENDENCY requires
	// INCONCLUSIVE; FAILED publishes none.
	Verdict *VerdictResult `json:"verdict,omitempty"`
	// Gaps carries the typed diagnostics. FAILED requires at least one.
	Gaps []AnalysisGap `json:"gaps,omitempty"`
	// ExternalDependencies is the published external answer and exists only
	// for EXTERNAL_DEPENDENCY, so an outcome consumer cannot read a failure as
	// an environmental abstention.
	ExternalDependencies []ExternalDependency `json:"external_dependencies,omitempty"`
	// Limitations retains supporting unknowns that cannot change this
	// result — including unknowns that are irrelevant to a sufficient proof.
	Limitations []string `json:"limitations,omitempty"`
}

// Validate enforces the frozen outcome/verdict invariants.
func (r AssessmentResult) Validate() error {
	if !r.Outcome.Valid() {
		return fmt.Errorf("assessment result: unknown outcome %q", r.Outcome)
	}
	if err := validateAnalysisGaps("assessment result gaps", r.Gaps); err != nil {
		return err
	}
	for n, dep := range r.ExternalDependencies {
		if err := dep.Validate(); err != nil {
			return fmt.Errorf("assessment result external_dependencies[%d]: %w", n, err)
		}
	}
	switch r.Outcome {
	case OutcomeDecided:
		if r.Verdict == nil {
			return fmt.Errorf("assessment result: %s requires a verdict", r.Outcome)
		}
		if !definitiveVerdict(r.Verdict.Verdict) {
			return fmt.Errorf("assessment result: %s verdict %q is not definitive", r.Outcome, r.Verdict.Verdict)
		}
		if len(r.ExternalDependencies) > 0 {
			return fmt.Errorf("assessment result: %s must not publish external dependencies", r.Outcome)
		}
		for _, gap := range r.Gaps {
			if gap.Owner == GapOwnerExternal {
				return fmt.Errorf("assessment result: %s retains an unresolved EXTERNAL gap %q", r.Outcome, gap.Code)
			}
		}
		return nil
	case OutcomeExternal:
		if r.Verdict == nil {
			return fmt.Errorf("assessment result: %s requires a verdict", r.Outcome)
		}
		if r.Verdict.Verdict != VerdictInconclusive {
			return fmt.Errorf("assessment result: %s verdict %q must be %q",
				r.Outcome, r.Verdict.Verdict, VerdictInconclusive)
		}
		if len(r.ExternalDependencies) == 0 {
			return fmt.Errorf("assessment result: %s requires at least one external dependency", r.Outcome)
		}
		for _, gap := range r.Gaps {
			if gap.Owner != GapOwnerExternal {
				return fmt.Errorf("assessment result: %s retains the analyzer-owned gap %s/%s; mixed blockers must fail",
					r.Outcome, gap.Owner, gap.Code)
			}
		}
		return nil
	default: // OutcomeFailed
		if r.Verdict != nil {
			return fmt.Errorf("assessment result: %s must not publish a verdict (got %q)", r.Outcome, r.Verdict.Verdict)
		}
		if len(r.Gaps) == 0 {
			return fmt.Errorf("assessment result: %s requires at least one typed analysis gap", r.Outcome)
		}
		if len(r.ExternalDependencies) > 0 {
			return fmt.Errorf("assessment result: %s must not publish external dependencies", r.Outcome)
		}
		return nil
	}
}

// ProfileAssessment is one threat profile's independent assessment of one
// record. Claims are that profile's own claim set — never another profile's or
// another record's — and Result is its terminal outcome.
type ProfileAssessment struct {
	Profile        ThreatProfile    `json:"profile"`
	IsTargetActual bool             `json:"is_target_actual"`
	Build          BuildContext     `json:"build"`
	Claims         []Claim          `json:"claims"`
	Result         AssessmentResult `json:"result"`
	ContextualRisk *ContextualRisk  `json:"contextual_risk,omitempty"`
}

// Validate enforces the profile record and every claim's structured gaps.
func (p ProfileAssessment) Validate() error {
	if !p.Profile.Known() {
		return fmt.Errorf("profile assessment: unknown threat profile %q", p.Profile)
	}
	for n, claim := range p.Claims {
		if err := validateAnalysisGaps(fmt.Sprintf("profile assessment %q claim %q", p.Profile, claim.ID), claim.AnalysisGaps); err != nil {
			return fmt.Errorf("claims[%d]: %w", n, err)
		}
	}
	if err := p.Result.Validate(); err != nil {
		return fmt.Errorf("profile assessment %q: %w", p.Profile, err)
	}
	return nil
}

// Known reports whether the threat profile is one of the frozen profiles.
func (p ThreatProfile) Known() bool {
	switch p {
	case ProfileZeroTrust, ProfileClusterPerimeter:
		return true
	default:
		return false
	}
}

// hasLimitation reports whether the exact mandatory limitation text is already
// present, so producers can append it idempotently.
func hasLimitation(limitations []string, text string) bool {
	return slices.Contains(limitations, text)
}

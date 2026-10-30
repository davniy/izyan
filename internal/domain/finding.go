package domain

import (
	"fmt"
	"strings"
)

// ProofOrigin names one independently admitted witness behind a positive
// requested finding: which assessment produced it, from which exact record
// bytes, for which affected entry and mechanism, under which profile and build,
// and with which qualified condition, claim and evidence references.
//
// An origin is either the primary record or one related record R. It is never
// an aggregate: the profile and build recorded here are the ones the witness
// was proved under, so two origins from different profiles or builds may not be
// combined into one positive.
type ProofOrigin struct {
	AssessmentID  CaseID         `json:"assessment_id"`
	Record        RecordPin      `json:"record"`
	EntryRefs     []int          `json:"entry_refs"`
	MechanismID   string         `json:"mechanism_id,omitempty"`
	AttributionID string         `json:"attribution_id,omitempty"`
	Profile       ThreatProfile  `json:"profile"`
	Build         BuildContext   `json:"build"`
	ConditionRefs []QualifiedRef `json:"condition_refs"`
	ClaimRefs     []QualifiedRef `json:"claim_refs"`
	EvidenceRefs  []QualifiedRef `json:"evidence_refs"`
}

// Validate enforces the attributed, evidence-bearing origin record. A positive
// without record bytes, a covered entry/mechanism or evidence references is a
// bare verdict and is rejected.
func (o ProofOrigin) Validate() error {
	if o.AssessmentID == "" {
		return fmt.Errorf("proof origin: assessment id is required")
	}
	if err := o.Record.Validate(); err != nil {
		return fmt.Errorf("proof origin %q: %w", o.AssessmentID, err)
	}
	if !o.Profile.Known() {
		return fmt.Errorf("proof origin %q: unknown threat profile %q", o.AssessmentID, o.Profile)
	}
	if err := validateEntryRefs("proof origin "+string(o.AssessmentID)+" entry refs", o.EntryRefs); err != nil {
		return err
	}
	if len(o.EntryRefs) == 0 && strings.TrimSpace(o.MechanismID) == "" {
		return fmt.Errorf("proof origin %q: a covered entry or mechanism is required", o.AssessmentID)
	}
	if err := validateQualifiedRefs("proof origin "+string(o.AssessmentID)+" condition refs", o.ConditionRefs); err != nil {
		return err
	}
	if err := validateQualifiedRefs("proof origin "+string(o.AssessmentID)+" claim refs", o.ClaimRefs); err != nil {
		return err
	}
	if len(o.EvidenceRefs) == 0 {
		return fmt.Errorf("proof origin %q: at least one evidence reference is required", o.AssessmentID)
	}
	if err := validateQualifiedRefs("proof origin "+string(o.AssessmentID)+" evidence refs", o.EvidenceRefs); err != nil {
		return err
	}
	return nil
}

// FindingProfile is one requested-finding result for one threat profile and
// build: the authoritative outcome, the public verdict (absent for FAILED), the
// exploitability scope, the proof origins of a positive, the declared corpus
// basis of a CVE-wide negative, and the external dependencies or typed gaps
// that explain an abstention or a failure.
type FindingProfile struct {
	Profile        ThreatProfile `json:"profile"`
	IsTargetActual bool          `json:"is_target_actual"`
	Build          BuildContext  `json:"build"`

	Outcome AssessmentOutcome `json:"assessment_outcome"`
	// Verdict is empty unless the outcome published one: DECIDED carries one
	// of the three definitive verdicts, EXTERNAL_DEPENDENCY carries
	// INCONCLUSIVE, and FAILED carries none.
	Verdict Verdict `json:"verdict,omitempty"`
	Reason  string  `json:"reason"`
	// ExploitabilityScope names the product boundary a positive covers:
	// library-api or transport-peer. Empty for every unscoped result.
	ExploitabilityScope ExploitabilityScope `json:"exploitability_scope,omitempty"`
	// ProofOrigins names the independently admitted witnesses of a positive.
	// A CVE positive may name only origins proved under this same profile and
	// build.
	ProofOrigins []ProofOrigin `json:"proof_origins,omitempty"`
	// CorpusNegativeBasis is the declared completeness basis of a CVE-wide
	// negative. It never replaces semantic proof.
	CorpusNegativeBasis  *CorpusNegativeBasis `json:"corpus_negative_basis,omitempty"`
	ExternalDependencies []ExternalDependency `json:"external_dependencies,omitempty"`
	Gaps                 []AnalysisGap        `json:"gaps,omitempty"`
	Limitations          []string             `json:"limitations,omitempty"`
}

// Validate enforces the frozen outcome, verdict, scope, origin and corpus
// invariants of one profile result.
func (p FindingProfile) Validate() error {
	if !p.Profile.Known() {
		return fmt.Errorf("finding profile: unknown threat profile %q", p.Profile)
	}
	if !p.Outcome.Valid() {
		return fmt.Errorf("finding profile %q: unknown outcome %q", p.Profile, p.Outcome)
	}
	if strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("finding profile %q: reason is required", p.Profile)
	}
	if p.Verdict != "" && !knownVerdict(p.Verdict) {
		return fmt.Errorf("finding profile %q: unknown verdict %q", p.Profile, p.Verdict)
	}
	if err := validateAnalysisGaps("finding profile "+string(p.Profile)+" gaps", p.Gaps); err != nil {
		return err
	}
	for n, dep := range p.ExternalDependencies {
		if err := dep.Validate(); err != nil {
			return fmt.Errorf("finding profile %q external_dependencies[%d]: %w", p.Profile, n, err)
		}
	}
	for n, origin := range p.ProofOrigins {
		if err := origin.Validate(); err != nil {
			return fmt.Errorf("finding profile %q proof_origins[%d]: %w", p.Profile, n, err)
		}
		if origin.Profile != p.Profile {
			return fmt.Errorf("finding profile %q proof_origins[%d]: origin profile %q is not this profile",
				p.Profile, n, origin.Profile)
		}
	}
	if p.ExploitabilityScope != "" {
		if !KnownExploitabilityScope(p.ExploitabilityScope) {
			return fmt.Errorf("finding profile %q: unknown exploitability scope %q", p.Profile, p.ExploitabilityScope)
		}
		if p.Verdict != VerdictExploitable {
			return fmt.Errorf("finding profile %q: exploitability scope %q requires an %q verdict",
				p.Profile, p.ExploitabilityScope, VerdictExploitable)
		}
		for _, limitation := range ExploitabilityScopeLimitations(p.ExploitabilityScope) {
			if !hasLimitation(p.Limitations, limitation) {
				return fmt.Errorf("finding profile %q: scope %q requires the mandatory limitation %q",
					p.Profile, p.ExploitabilityScope, limitation)
			}
		}
	}
	if p.CorpusNegativeBasis != nil {
		if p.Verdict != VerdictNotAffected {
			return fmt.Errorf("finding profile %q: a corpus negative basis requires an %q verdict, got %q",
				p.Profile, VerdictNotAffected, p.Verdict)
		}
		if err := p.CorpusNegativeBasis.Validate(); err != nil {
			return fmt.Errorf("finding profile %q: %w", p.Profile, err)
		}
	}
	switch p.Outcome {
	case OutcomeDecided:
		if !definitiveVerdict(p.Verdict) {
			return fmt.Errorf("finding profile %q: %s verdict %q is not definitive", p.Profile, p.Outcome, p.Verdict)
		}
		if len(p.ExternalDependencies) > 0 {
			return fmt.Errorf("finding profile %q: %s must not publish external dependencies", p.Profile, p.Outcome)
		}
		for _, gap := range p.Gaps {
			if gap.Owner == GapOwnerExternal {
				return fmt.Errorf("finding profile %q: %s retains the unresolved EXTERNAL gap %q",
					p.Profile, p.Outcome, gap.Code)
			}
		}
		if p.Verdict == VerdictExploitable && len(p.ProofOrigins) == 0 {
			return fmt.Errorf("finding profile %q: an %q verdict requires at least one proof origin",
				p.Profile, p.Verdict)
		}
		return nil
	case OutcomeExternal:
		if p.Verdict != VerdictInconclusive {
			return fmt.Errorf("finding profile %q: %s verdict %q must be %q",
				p.Profile, p.Outcome, p.Verdict, VerdictInconclusive)
		}
		if len(p.ExternalDependencies) == 0 {
			return fmt.Errorf("finding profile %q: %s requires at least one external dependency", p.Profile, p.Outcome)
		}
		for _, gap := range p.Gaps {
			if gap.Owner != GapOwnerExternal {
				return fmt.Errorf("finding profile %q: %s retains the analyzer-owned gap %s/%s; mixed blockers must fail",
					p.Profile, p.Outcome, gap.Owner, gap.Code)
			}
		}
		return nil
	default: // OutcomeFailed
		if p.Verdict != "" {
			return fmt.Errorf("finding profile %q: %s must not publish a verdict (got %q)", p.Profile, p.Outcome, p.Verdict)
		}
		if len(p.Gaps) == 0 {
			return fmt.Errorf("finding profile %q: %s requires at least one typed analysis gap", p.Profile, p.Outcome)
		}
		if len(p.ExternalDependencies) > 0 {
			return fmt.Errorf("finding profile %q: %s must not publish external dependencies", p.Profile, p.Outcome)
		}
		return nil
	}
}

// RequestedFinding is the single authoritative answer to the caller's request.
// Every output — JSON, Markdown, CLI, scan/eval, tracker, justification,
// remediation, research, OpenVEX and CycloneDX — projects this one record.
//
// The embedded FindingProfile is the actual profile's result for a FINAL
// envelope. Profiles retains every other profile's independent result so a
// hypothetical profile is never presented as the deployment's answer.
type RequestedFinding struct {
	Status              FindingStatus     `json:"status"`
	RequestedID         string            `json:"requested_id"`
	RequestedKind       AdvisoryScopeKind `json:"requested_kind"`
	Coverage            AdvisoryCoverage  `json:"coverage"`
	PrimaryAssessmentID CaseID            `json:"primary_assessment_id"`

	FindingProfile
	Profiles []FindingProfile `json:"profiles,omitempty"`
}

// Validate enforces the envelope, the actual result and the profile set.
func (f RequestedFinding) Validate() error {
	if !f.Status.Valid() {
		return fmt.Errorf("requested finding: unknown status %q", f.Status)
	}
	if strings.TrimSpace(f.RequestedID) == "" {
		return fmt.Errorf("requested finding: requested id is required")
	}
	switch f.RequestedKind {
	case ScopeAdvisoryEntries, ScopeCVE:
	default:
		return fmt.Errorf("requested finding %q: unknown requested kind %q", f.RequestedID, f.RequestedKind)
	}
	switch f.Coverage {
	case CoverageComplete, CoverageKnownOnly:
	default:
		return fmt.Errorf("requested finding %q: unknown coverage %q", f.RequestedID, f.Coverage)
	}
	if f.RequestedKind == ScopeCVE && f.Coverage != CoverageKnownOnly {
		return fmt.Errorf("requested finding %q: a CVE request keeps %q coverage; corpus authority travels in corpus_negative_basis",
			f.RequestedID, CoverageKnownOnly)
	}
	if f.PrimaryAssessmentID == "" {
		return fmt.Errorf("requested finding %q: primary assessment id is required", f.RequestedID)
	}
	if f.Status == FindingPending {
		if f.Outcome != "" || f.Verdict != "" {
			return fmt.Errorf("requested finding %q: PENDING is a persistence phase and must not claim an outcome or verdict",
				f.RequestedID)
		}
		return nil
	}
	if err := f.FindingProfile.Validate(); err != nil {
		return fmt.Errorf("requested finding %q: %w", f.RequestedID, err)
	}
	if f.RequestedKind == ScopeCVE && f.Verdict == VerdictNotAffected && f.CorpusNegativeBasis == nil {
		return fmt.Errorf("requested finding %q: a CVE-wide %q requires a declared corpus negative basis",
			f.RequestedID, VerdictNotAffected)
	}
	for n, profile := range f.Profiles {
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("requested finding %q profiles[%d]: %w", f.RequestedID, n, err)
		}
		if !profile.IsTargetActual {
			continue
		}
		if !f.IsTargetActual {
			return fmt.Errorf("requested finding %q: profiles[%d] claims to be the target actual profile but the requested result is not marked actual",
				f.RequestedID, n)
		}
		if profile.Profile != f.Profile || profile.Outcome != f.Outcome || profile.Verdict != f.Verdict {
			return fmt.Errorf("requested finding %q: profiles[%d] (%s/%s/%q) disagrees with the requested result (%s/%s/%q)",
				f.RequestedID, n, profile.Profile, profile.Outcome, profile.Verdict,
				f.Profile, f.Outcome, f.Verdict)
		}
	}
	return nil
}

// RelatedRecordAssessment is one related candidate record's own assessment,
// retained beside the requested finding. The nested case is a pointer on
// purpose: an analysis case owns a mutex and an evidence graph, so it is never
// copied by value.
type RelatedRecordAssessment struct {
	ID       CaseID        `json:"id"`
	Record   RecordPin     `json:"record"`
	Analysis *AnalysisCase `json:"analysis,omitempty"`
}

// Validate enforces the related-assessment identity and its pinned record. The
// nested case is validated by AnalysisCase.ValidateCaseResult.
func (r RelatedRecordAssessment) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("related record assessment: assessment id is required")
	}
	if err := r.Record.Validate(); err != nil {
		return fmt.Errorf("related record assessment %q: %w", r.ID, err)
	}
	return nil
}

// Package finding's projection is the single publication gate for a persisted
// requested finding. Project re-admits every proof artifact a saved case
// carries, recomposes the request from the current record assessments and
// refuses a saved conclusion the current admission no longer supports.
package finding

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/fixbinding"
)

// ErrLegacyCase marks a legacy single-assessment case: it has no
// analysis-case/2 requested-finding projection. Its historical verdict is
// preserved verbatim and must never be reinterpreted as a requested outcome,
// discovery claim, attribution or external dependency.
var ErrLegacyCase = errors.New("legacy case has no requested-finding projection")

// ErrPolicyDrift marks a persisted requested finding whose recomposition under
// the current admission no longer equals the saved envelope.
var ErrPolicyDrift = errors.New("persisted requested finding differs from current admission")

// LegacyCaseError reports a case that cannot be published through the
// requested-finding projection because it predates that contract. Pending is
// set when the case already carries new-contract data but never composed its
// envelope: it may still be resumed, but not published.
type LegacyCaseError struct {
	AssessmentID domain.CaseID
	Pending      bool
}

func (e *LegacyCaseError) Error() string {
	if e.Pending {
		return fmt.Sprintf("analysis case %q: the requested finding was never composed; a pending case is not publishable", e.AssessmentID)
	}
	return fmt.Sprintf("analysis case %q: a legacy single-assessment case has no requested-finding projection; its historical classification must not be read as a requested outcome, discovery claim, attribution or verified external dependency", e.AssessmentID)
}

func (e *LegacyCaseError) Is(target error) bool { return target == ErrLegacyCase }

// PolicyDriftError reports that the saved requested finding is not the result
// current admission recomposes. The saved closure is refused, never silently
// declared equivalent.
type PolicyDriftError struct {
	AssessmentID domain.CaseID
	Fields       []string
	Saved        domain.RequestedFinding
	Recomposed   domain.RequestedFinding
}

func (e *PolicyDriftError) Error() string {
	return fmt.Sprintf("analysis case %q: the persisted requested finding no longer matches current admission (policy drift: %s); the saved conclusion is refused",
		e.AssessmentID, strings.Join(e.Fields, ", "))
}

func (e *PolicyDriftError) Is(target error) bool { return target == ErrPolicyDrift }

// WitnessView is one independently admitted proof origin together with the
// assessment and profile result that produced it. Consumers render the proof
// from this view; they never reconstruct a witness from the requested finding
// alone.
type WitnessView struct {
	Origin     domain.ProofOrigin
	Assessment *domain.AnalysisCase
	Profile    domain.ProfileAssessment
}

// View is the one authoritative publication projection of a requested finding:
// the recomposed envelope, the primary assessment, every independently assessed
// record and every witness behind a positive profile.
type View struct {
	Requested domain.RequestedFinding
	Primary   *domain.AnalysisCase
	Records   map[domain.CaseID]*domain.AnalysisCase
	Witnesses []WitnessView
	// Axes is the derived two-question presentation of the same admission:
	// vulnerable code/version in the assessed build, and exploitability in
	// the assessed scope. It is display-only and never proof; every
	// authoritative conclusion remains in Requested and the record cases.
	Axes AssessmentAxes
}

// Project re-admits one persisted analysis case and returns its publication
// projection. It is pure: no field of c is read through a path that mutates it,
// and the returned View is built from fresh slices and maps.
//
// Project refuses to publish:
//
//   - a legacy or still-pending case (no analysis-case/2 envelope);
//   - a case whose structural result or child/disposition shape is invalid;
//   - a profile result whose claims and affected facts no longer classify to
//     the saved outcome, verdict, scope, evidence set or external dependency;
//   - a record pin, build binding, profile identity, attribution or transport
//     witness that does not re-admit against the persisted evidence;
//   - qualified references that do not resolve inside their named assessment;
//   - a saved envelope that differs from the recomposed projection.
func Project(c *domain.AnalysisCase) (View, error) {
	if c == nil {
		return View{}, fmt.Errorf("project requested finding: nil analysis case")
	}
	if c.Schema != domain.CaseSchemaV2 {
		if err := domain.ValidateCaseResult(c); err != nil {
			return View{}, fmt.Errorf("project requested finding: %w", err)
		}
		return View{}, &LegacyCaseError{AssessmentID: c.ID, Pending: c.HasRequestContractFields()}
	}
	if err := domain.ValidateFinalizedCase(c); err != nil {
		return View{}, fmt.Errorf("project requested finding: %w", err)
	}
	requestedID, kind, _ := domain.RequestedIdentity(c)
	if requestedID == "" {
		return View{}, fmt.Errorf("project requested finding: analysis case %q carries no request identity", c.ID)
	}

	records, err := caseRecords(c)
	if err != nil {
		return View{}, err
	}
	for _, record := range orderedRecords(c, records) {
		if err := admitRecord(record); err != nil {
			return View{}, fmt.Errorf("project requested finding: assessment %q: %w", record.ID, err)
		}
	}
	if err := admitDiscovery(c); err != nil {
		return View{}, fmt.Errorf("project requested finding: %w", err)
	}
	if err := admitAttributions(c, requestedID, kind); err != nil {
		return View{}, fmt.Errorf("project requested finding: %w", err)
	}

	recomposed, err := Compose(c)
	if err != nil {
		return View{}, fmt.Errorf("project requested finding: recompose: %w", err)
	}
	if drift := requestedDrift(*c.RequestedFinding, recomposed); len(drift) > 0 {
		return View{}, &PolicyDriftError{
			AssessmentID: c.ID,
			Fields:       drift,
			Saved:        *c.RequestedFinding,
			Recomposed:   recomposed,
		}
	}
	witnesses, err := projectWitnesses(c, requestedID, recomposed, records)
	if err != nil {
		return View{}, fmt.Errorf("project requested finding: %w", err)
	}
	axes, err := deriveAxes(recomposed, c, orderedRecords(c, records))
	if err != nil {
		return View{}, fmt.Errorf("project requested finding: %w", err)
	}
	return View{
		Requested: recomposed,
		Primary:   c,
		Records:   records,
		Witnesses: witnesses,
		Axes:      axes,
	}, nil
}

// caseRecords indexes the primary and every independently assessed child. A
// duplicate assessment id would make a witness ambiguous, so it is rejected.
func caseRecords(c *domain.AnalysisCase) (map[domain.CaseID]*domain.AnalysisCase, error) {
	records := make(map[domain.CaseID]*domain.AnalysisCase, 1+len(c.RelatedRecords))
	if c.ID == "" {
		return nil, fmt.Errorf("analysis case has no assessment id")
	}
	records[c.ID] = c
	for _, related := range c.RelatedRecords {
		if related.Analysis == nil {
			continue
		}
		if _, exists := records[related.ID]; exists {
			return nil, fmt.Errorf("assessment id %q is used by more than one record", related.ID)
		}
		records[related.ID] = related.Analysis
	}
	return records, nil
}

func orderedRecords(c *domain.AnalysisCase, records map[domain.CaseID]*domain.AnalysisCase) []*domain.AnalysisCase {
	ordered := make([]*domain.AnalysisCase, 0, len(records))
	ordered = append(ordered, records[c.ID])
	for _, related := range c.RelatedRecords {
		if related.Analysis == nil {
			continue
		}
		ordered = append(ordered, records[related.ID])
	}
	return ordered
}

// admitRecord re-admits one record's profile assessments against the record's
// own persisted claims, affected facts, exploit model, root cause and
// evidence. A saved result the current classifier no longer produces is not
// publishable, and every profile must be bound to the record's effective build
// with exactly one actual profile.
func admitRecord(c *domain.AnalysisCase) error {
	if len(c.ProfileAssessments) == 0 {
		// A record that never reached evaluation contributes no profile
		// result; composition reports the record-level failure from its typed
		// gaps.
		return nil
	}
	if _, ok := targetActual(c); !ok {
		return fmt.Errorf("profile assessments carry no unique target-actual profile")
	}
	seen := make(map[domain.ThreatProfile]bool, len(c.ProfileAssessments))
	effective := domain.EffectiveBuildContext(c.Product)
	for n, assessment := range c.ProfileAssessments {
		if seen[assessment.Profile] {
			return fmt.Errorf("profile_assessments[%d]: profile %q is listed twice", n, assessment.Profile)
		}
		seen[assessment.Profile] = true
		if err := assessment.Build.Matches(effective); err != nil {
			return fmt.Errorf("profile_assessments[%d] (%s): assessment build is not the record's effective build: %w",
				n, assessment.Profile, err)
		}
		if err := admitProfileResult(c, assessment); err != nil {
			return fmt.Errorf("profile_assessments[%d] (%s): %w", n, assessment.Profile, err)
		}
		if err := admitTransportProof(c, assessment); err != nil {
			return fmt.Errorf("profile_assessments[%d] (%s): %w", n, assessment.Profile, err)
		}
	}
	return nil
}

func targetActual(c *domain.AnalysisCase) (domain.ProfileAssessment, bool) {
	var found domain.ProfileAssessment
	count := 0
	for _, assessment := range c.ProfileAssessments {
		if !assessment.IsTargetActual {
			continue
		}
		found = assessment
		count++
	}
	if count != 1 {
		return domain.ProfileAssessment{}, false
	}
	return found, true
}

// admitProfileResult recomputes the record's classification from the saved
// profile claims and compares it with the saved result. Case-level producer
// gaps are deliberately not re-fed: the saved diagnostics are already
// validated structurally, and the classifier grants a sufficient proof
// precedence over unrelated blockers.
func admitProfileResult(c *domain.AnalysisCase, assessment domain.ProfileAssessment) error {
	saved := assessment.Result
	recomputed := Assess(AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Product:   c.Product,
			Affected:  affectedOf(c),
			Model:     modelOf(c),
			Claims:    assessment.Claims,
			Evidence:  c.EvidenceGraph.EvidenceList(),
			RecordPin: c.RecordPin,
			AdvisoryRecord: c.AdvisoryRecord,
			// The saved claims are re-established against the case that
			// owns their evidence: a persisted TRUE is a value, not proof.
			Case: c,
		},
		RootCause:     c.RootCause,
		Vulnerability: c.Vulnerability,
		AssessmentID:  c.ID,
	})
	if err := compareSavedResult(c, assessment, saved, recomputed); err != nil {
		return fmt.Errorf("saved %s result is not supported by the current record assessment: %w",
			saved.Outcome, err)
	}
	return nil
}

func compareSavedResult(c *domain.AnalysisCase, assessment domain.ProfileAssessment, saved, recomputed domain.AssessmentResult) error {
	switch saved.Outcome {
	case domain.OutcomeDecided:
		if recomputed.Outcome != domain.OutcomeDecided || recomputed.Verdict == nil {
			return fmt.Errorf("re-evaluation yields %s/%q", recomputed.Outcome, verdictOfResult(recomputed))
		}
		if saved.Verdict == nil {
			return fmt.Errorf("decided result carries no verdict")
		}
		if saved.Verdict.Verdict != recomputed.Verdict.Verdict {
			return fmt.Errorf("verdict %q re-evaluates to %q", saved.Verdict.Verdict, recomputed.Verdict.Verdict)
		}
		if saved.Verdict.ExploitabilityScope != recomputed.Verdict.ExploitabilityScope {
			return fmt.Errorf("scope %q re-evaluates to %q",
				saved.Verdict.ExploitabilityScope, recomputed.Verdict.ExploitabilityScope)
		}
		if saved.Verdict.GroundBasis != recomputed.Verdict.GroundBasis {
			return fmt.Errorf("ground basis %q re-evaluates to %q",
				saved.Verdict.GroundBasis, recomputed.Verdict.GroundBasis)
		}
		if !sameConditionIDs(saved.Verdict.ConditionIDs, recomputed.Verdict.ConditionIDs) {
			return fmt.Errorf("verdict condition references do not re-admit")
		}
		if !sameEvidenceIDs(saved.Verdict.EvidenceIDs, recomputed.Verdict.EvidenceIDs) {
			return fmt.Errorf("verdict evidence references do not re-admit")
		}
		if !sameStrings(saved.Verdict.AssumptionIDs, recomputed.Verdict.AssumptionIDs) {
			return fmt.Errorf("verdict assumption references do not re-admit")
		}
		return nil
	case domain.OutcomeExternal:
		if recomputed.Outcome != domain.OutcomeExternal {
			return fmt.Errorf("re-evaluation yields %s, not an external dependency", recomputed.Outcome)
		}
		if saved.Verdict == nil || saved.Verdict.Verdict != domain.VerdictInconclusive {
			return fmt.Errorf("external outcome does not carry an INCONCLUSIVE verdict")
		}
		if !sameDependencies(saved.ExternalDependencies, recomputed.ExternalDependencies) {
			return fmt.Errorf("external dependencies do not re-admit against the record facts")
		}
		return nil
	default: // FAILED
		if saved.Verdict != nil {
			return fmt.Errorf("failed outcome publishes verdict %q", saved.Verdict.Verdict)
		}
		if recomputed.Outcome == domain.OutcomeDecided {
			if recomputed.Verdict != nil && recomputed.Verdict.Verdict == domain.VerdictNoExploitPathFound &&
				operatorDemotionExplained(c, assessment, saved, recomputed) {
				// The cluster-perimeter state demotes an operator-declared
				// trusted NEPF to FAILED when the model still carries
				// unmodeled sink subjects. The claim set still re-admits; the
				// saved failure is that recorded demotion, not a forged one.
				return nil
			}
			return fmt.Errorf("re-evaluation yields the definitive verdict %q, so the saved failure is unsupported",
				verdictOfResult(recomputed))
		}
		return nil
	}
}

// operatorDemotionExplained recognises the one legitimate state-level overlay
// between the evaluator and a saved FAILED result: EvaluateVerdict demotes an
// operator-declared trusted-infrastructure NEPF when advisory-declared sinks
// remain unmodeled. Without this narrow match a saved failure may not hide a
// recomputed definitive negative.
func operatorDemotionExplained(c *domain.AnalysisCase, assessment domain.ProfileAssessment, saved, recomputed domain.AssessmentResult) bool {
	if !hasGapCode(saved.Gaps, domain.GapReachabilityProofIncomplete) {
		return false
	}
	operatorAsserted := c.Product.TrustedPeer ||
		(c.Product.PerimeterOverride != "" && c.Product.PerimeterOverride != "auto")
	if !operatorAsserted {
		return false
	}
	model := modelOf(c)
	// The absent set is a saved conclusion. Count only the subjects this
	// record's admission still establishes; an unadmitted entry is blocking,
	// not proof that a sink was absent from the build.
	proof := fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(c), c.RootCause)
	absenceAdmission := domain.AdmitAbsence(c, affected.AdmittedBuildGraph(c.Product, c.EvidenceGraph.EvidenceList()), proof)
	absent := make(map[domain.SymbolRef]bool, len(model.AbsentSubjects))
	for _, subject := range model.AbsentSubjects {
		if absenceAdmission.Admits(subject).Admitted {
			absent[subject] = true
		}
	}
	unmodeled := 0
	for _, subject := range model.UnresolvedSubjects {
		if !absent[subject] {
			unmodeled++
		}
	}
	if unmodeled == 0 {
		return false
	}
	if len(recomputed.Verdict.ConditionIDs) == 0 {
		return false
	}
	for _, id := range recomputed.Verdict.ConditionIDs {
		for _, claim := range assessment.Claims {
			if claim.ConditionID == id && claim.Falsifier == domain.FalsifierTrustedInfrastructure {
				return true
			}
		}
	}
	return false
}

func hasGapCode(gaps []domain.AnalysisGap, code domain.GapCode) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

// admitTransportProof re-admits every transport witness a saved claim relies
// on. The verdict evaluator already re-admits the rooted input witness behind a
// transport-peer scope; this gate also re-admits the source/fix-bound trigger
// witness behind a mechanism claim, which the verdict conjunction alone does
// not inspect.
func admitTransportProof(c *domain.AnalysisCase, assessment domain.ProfileAssessment) error {
	evidence := c.EvidenceGraph.EvidenceList()
	model := modelOf(c)
	for _, claim := range assessment.Claims {
		condition, ok := mandatoryCondition(model, claim.ConditionID)
		if !ok || claim.Result != domain.ClaimTrue {
			continue
		}
		if claim.ControlBasis == domain.ControlBasisTransportPeerInput {
			if err := evaluator.ValidateTransportInput(c.Product, model, claim, evidence); err != nil {
				return fmt.Errorf("transport input claim %q: %w", claim.ConditionID, err)
			}
		}
		if condition.Params[domain.ParamMechanism] != "" {
			if err := evaluator.ValidateTransportTrigger(c.Product, model, claim, evidence); err != nil {
				return fmt.Errorf("transport trigger claim %q: %w", claim.ConditionID, err)
			}
		}
	}
	if assessment.Result.Verdict == nil ||
		assessment.Result.Verdict.ExploitabilityScope != domain.ScopeTransportPeer {
		return nil
	}
	input, _ := domain.TransportWitnessFromEvidence(evidence)
	if input == nil {
		return fmt.Errorf("transport-peer scope has no rooted transport input witness")
	}
	if err := input.Complete(); err != nil {
		return fmt.Errorf("transport-peer scope witness: %w", err)
	}
	if c.RecordPin == nil || !input.Record.Same(*c.RecordPin) {
		return fmt.Errorf("transport-peer witness pins different record bytes")
	}
	if err := input.Build.Matches(domain.EffectiveBuildContext(c.Product)); err != nil {
		return fmt.Errorf("transport-peer witness build is not the record build: %w", err)
	}
	resolved := make(map[domain.EvidenceID]bool, len(evidence))
	for _, item := range evidence {
		resolved[item.ID] = true
	}
	for _, id := range input.EvidenceIDs {
		if !resolved[id] {
			return fmt.Errorf("transport-peer witness cites missing evidence %q", id)
		}
	}
	return nil
}

// admitDiscovery re-admits the discovery record against the observed corpus
// manifest: the corpus identity and every nominated document pin must still
// agree, so a rewritten candidate set cannot stand on a manifest that never
// enumerated it.
func admitDiscovery(c *domain.AnalysisCase) error {
	requestedID, _, _ := domain.RequestedIdentity(c)
	if c.RelatedDiscovery == nil {
		if len(c.RelatedRecords) > 0 {
			return fmt.Errorf("related assessments require a discovery record")
		}
		return nil
	}
	discovery := c.RelatedDiscovery
	if discovery.RequestedID != requestedID {
		return fmt.Errorf("discovery requested id %q is not the case request %q", discovery.RequestedID, requestedID)
	}
	if c.CorpusManifest == nil {
		return nil
	}
	manifest := *c.CorpusManifest
	if discovery.Corpus != nil {
		if discovery.Corpus.Reference != manifest.Reference ||
			discovery.Corpus.Digest != manifest.ObservedDigest {
			return fmt.Errorf("discovery pins corpus %q (%s), the manifest observes %q (%s)",
				discovery.Corpus.Reference, discovery.Corpus.Digest,
				manifest.Reference, manifest.ObservedDigest)
		}
	}
	for _, candidate := range discovery.Candidates {
		if !manifest.Pins(candidate.Record) {
			return fmt.Errorf("nominated candidate %q (%s) is not pinned by the observed corpus manifest",
				candidate.Record.RecordID, candidate.Record.DocumentDigest)
		}
		if candidate.Disposition == domain.DispositionEvaluated {
			if child := relatedChild(c, candidate.Record); child == nil {
				return fmt.Errorf("evaluated candidate %q (%s) has no independent assessment",
					candidate.Record.RecordID, candidate.Record.DocumentDigest)
			}
		}
	}
	return nil
}

func relatedChild(c *domain.AnalysisCase, pin domain.RecordPin) *domain.AnalysisCase {
	for _, related := range c.RelatedRecords {
		if related.Record.Same(pin) {
			return related.Analysis
		}
	}
	return nil
}

// admitAttributions re-admits the directional CVE propositions that may bind a
// record's own positive to the request. A stored attribution for another CVE,
// or an exact-record request carrying request-level attributions, is refused.
func admitAttributions(c *domain.AnalysisCase, requestedID string, kind domain.AdvisoryScopeKind) error {
	if kind != domain.ScopeCVE {
		if len(c.Attributions) > 0 {
			return fmt.Errorf("an exact-record request may not carry request-level CVE attributions")
		}
		return nil
	}
	ids := make(map[string]bool, len(c.Attributions))
	for n, attribution := range c.Attributions {
		if err := attribution.Validate(); err != nil {
			return fmt.Errorf("attributions[%d]: %w", n, err)
		}
		if ids[attribution.ID] {
			return fmt.Errorf("attributions[%d]: attribution id %q is listed twice", n, attribution.ID)
		}
		ids[attribution.ID] = true
		if !strings.EqualFold(attribution.CVEID, requestedID) {
			return fmt.Errorf("attributions[%d]: attribution %q names CVE %q, the request is %q",
				n, attribution.ID, attribution.CVEID, requestedID)
		}
	}
	return nil
}

// projectWitnesses turns every recomposed proof origin into a witness view and
// re-admits its record pin, build, profile, attribution, qualified references
// and record binding.
func projectWitnesses(c *domain.AnalysisCase, requestedID string, requested domain.RequestedFinding,
	records map[domain.CaseID]*domain.AnalysisCase) ([]WitnessView, error) {
	profiles := requested.Profiles
	if len(profiles) == 0 {
		profiles = []domain.FindingProfile{requested.FindingProfile}
	}
	var witnesses []WitnessView
	for _, profile := range profiles {
		for n, origin := range profile.ProofOrigins {
			record := records[origin.AssessmentID]
			if record == nil {
				return nil, fmt.Errorf("profile %q proof_origins[%d]: assessment %q is not an assessed record",
					profile.Profile, n, origin.AssessmentID)
			}
			assessment, ok := domain.ProfileAssessmentFor(record, origin.Profile)
			if !ok {
				return nil, fmt.Errorf("profile %q proof_origins[%d]: assessment %q has no %q profile result",
					profile.Profile, n, origin.AssessmentID, origin.Profile)
			}
			if err := admitOrigin(c, requestedID, record, assessment, origin); err != nil {
				return nil, fmt.Errorf("profile %q proof_origins[%d]: %w", profile.Profile, n, err)
			}
			witnesses = append(witnesses, WitnessView{
				Origin:     origin,
				Assessment: record,
				Profile:    assessment,
			})
		}
	}
	return witnesses, nil
}

// admitOrigin re-admits one publication-grade witness: its assessment, exact
// record bytes, profile and build, admitted attribution, qualified condition,
// claim and evidence references and its affected-entry/mechanism binding.
func admitOrigin(root *domain.AnalysisCase, requestedID string, record *domain.AnalysisCase,
	assessment domain.ProfileAssessment, origin domain.ProofOrigin) error {
	if err := origin.Validate(); err != nil {
		return err
	}
	if record.RecordPin == nil || !origin.Record.Same(*record.RecordPin) {
		return fmt.Errorf("witness record pin does not identify assessment %q's exact bytes", record.ID)
	}
	if origin.Profile != assessment.Profile {
		return fmt.Errorf("witness profile %q is not assessment %q's %q result",
			origin.Profile, record.ID, assessment.Profile)
	}
	if err := origin.Build.Matches(domain.EffectiveBuildContext(record.Product)); err != nil {
		return fmt.Errorf("witness build is not the assessment's build: %w", err)
	}
	attribution := attributionForPin(root, record.RecordPin, origin.AttributionID)
	if origin.AttributionID != "" {
		if attribution == nil || !attribution.Admitted() {
			return fmt.Errorf("witness attribution %q is not an admitted attribution for the record",
				origin.AttributionID)
		}
		if !strings.EqualFold(attribution.CVEID, requestedID) {
			return fmt.Errorf("witness attribution %q names CVE %q, the request is %q",
				origin.AttributionID, attribution.CVEID, requestedID)
		}
		if !attribution.Candidate.Same(origin.Record) {
			return fmt.Errorf("witness attribution %q pins different record bytes", origin.AttributionID)
		}
	}
	model := modelOf(record)
	conditions := make(map[domain.ConditionID]bool, len(model.MandatoryConditions))
	for _, condition := range model.MandatoryConditions {
		conditions[condition.ID] = true
	}
	claims := make(map[domain.ClaimID]domain.Claim, len(record.Claims))
	for _, claim := range record.Claims {
		claims[claim.ID] = claim
	}
	evidenceList := record.EvidenceGraph.EvidenceList()
	evidence := make(map[domain.EvidenceID]bool, len(evidenceList))
	for _, item := range evidenceList {
		evidence[item.ID] = true
	}
	for n, ref := range origin.ConditionRefs {
		if ref.AssessmentID != record.ID {
			return fmt.Errorf("condition_refs[%d] is qualified to assessment %q, not %q",
				n, ref.AssessmentID, record.ID)
		}
		if !conditions[domain.ConditionID(ref.Ref)] {
			return fmt.Errorf("condition_refs[%d] names no mandatory condition %q", n, ref.Ref)
		}
	}
	for n, ref := range origin.ClaimRefs {
		if ref.AssessmentID != record.ID {
			return fmt.Errorf("claim_refs[%d] is qualified to assessment %q, not %q",
				n, ref.AssessmentID, record.ID)
		}
		claim, ok := claims[domain.ClaimID(ref.Ref)]
		if !ok {
			return fmt.Errorf("claim_refs[%d] names no claim %q in assessment %q", n, ref.Ref, record.ID)
		}
		if !conditions[claim.ConditionID] {
			return fmt.Errorf("claim_refs[%d] names claim %q outside the witness conditions", n, ref.Ref)
		}
	}
	for n, ref := range origin.EvidenceRefs {
		if ref.AssessmentID != record.ID {
			return fmt.Errorf("evidence_refs[%d] is qualified to assessment %q, not %q",
				n, ref.AssessmentID, record.ID)
		}
		if !evidence[domain.EvidenceID(ref.Ref)] {
			return fmt.Errorf("evidence_refs[%d] names no evidence %q in assessment %q",
				n, ref.Ref, record.ID)
		}
	}
	wantEntries, wantMechanism := originBinding(record, attribution)
	if !slices.Equal(wantEntries, origin.EntryRefs) {
		return fmt.Errorf("entry refs %v do not re-admit the record binding %v", origin.EntryRefs, wantEntries)
	}
	if wantMechanism != origin.MechanismID {
		return fmt.Errorf("mechanism %q does not re-admit the record binding %q", origin.MechanismID, wantMechanism)
	}
	return nil
}

// requestedDrift names every top-level field by which a saved requested
// finding differs from the current recomposition.
func requestedDrift(saved, recomposed domain.RequestedFinding) []string {
	var fields []string
	add := func(name string, different bool) {
		if different {
			fields = append(fields, name)
		}
	}
	add("status", saved.Status != recomposed.Status)
	add("requested_id", saved.RequestedID != recomposed.RequestedID)
	add("requested_kind", saved.RequestedKind != recomposed.RequestedKind)
	add("coverage", saved.Coverage != recomposed.Coverage)
	add("primary_assessment_id", saved.PrimaryAssessmentID != recomposed.PrimaryAssessmentID)
	add("profile", saved.Profile != recomposed.Profile)
	add("is_target_actual", saved.IsTargetActual != recomposed.IsTargetActual)
	add("build", !reflect.DeepEqual(saved.Build, recomposed.Build))
	add("assessment_outcome", saved.Outcome != recomposed.Outcome)
	add("verdict", saved.Verdict != recomposed.Verdict)
	add("reason", saved.Reason != recomposed.Reason)
	add("exploitability_scope", saved.ExploitabilityScope != recomposed.ExploitabilityScope)
	add("proof_origins", !reflect.DeepEqual(saved.ProofOrigins, recomposed.ProofOrigins))
	add("corpus_negative_basis", !reflect.DeepEqual(saved.CorpusNegativeBasis, recomposed.CorpusNegativeBasis))
	add("external_dependencies", !reflect.DeepEqual(saved.ExternalDependencies, recomposed.ExternalDependencies))
	add("gaps", !reflect.DeepEqual(saved.Gaps, recomposed.Gaps))
	add("limitations", !reflect.DeepEqual(saved.Limitations, recomposed.Limitations))
	add("profiles", !reflect.DeepEqual(saved.Profiles, recomposed.Profiles))
	return fields
}

func affectedOf(c *domain.AnalysisCase) domain.AffectedResult {
	if c != nil && c.Affected != nil {
		return *c.Affected
	}
	return domain.AffectedResult{}
}

func modelOf(c *domain.AnalysisCase) domain.ExploitModel {
	if c != nil && c.Exploit != nil {
		return *c.Exploit
	}
	return domain.ExploitModel{}
}

func mandatoryCondition(model domain.ExploitModel, id domain.ConditionID) (domain.Condition, bool) {
	for _, condition := range model.MandatoryConditions {
		if condition.ID == id {
			return condition, true
		}
	}
	return domain.Condition{}, false
}

func sameConditionIDs(left, right []domain.ConditionID) bool {
	if len(left) != len(right) {
		return false
	}
	return sameStringSet(stringsOf(left), stringsOf(right))
}

func sameEvidenceIDs(left, right []domain.EvidenceID) bool {
	if len(left) != len(right) {
		return false
	}
	return sameStringSet(stringsOf(left), stringsOf(right))
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	return sameStringSet(left, right)
}

func stringsOf[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = string(value)
	}
	return out
}

func sameStringSet(left, right []string) bool {
	leftSet := make(map[string]int, len(left))
	for _, value := range left {
		leftSet[value]++
	}
	for _, value := range right {
		leftSet[value]--
		if leftSet[value] < 0 {
			return false
		}
	}
	for _, remaining := range leftSet {
		if remaining != 0 {
			return false
		}
	}
	return true
}

// sameDependencies compares saved external dependencies with the ones the
// current classifier derives. Ordering is irrelevant; the missing fact, the
// affected obligation and the boundary references must all re-admit.
func sameDependencies(left, right []domain.ExternalDependency) bool {
	if len(left) != len(right) {
		return false
	}
	used := make([]bool, len(right))
	for _, dependency := range left {
		found := false
		for i, candidate := range right {
			if used[i] {
				continue
			}
			if reflect.DeepEqual(dependency, candidate) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

package research

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/finding"
	"github.com/davniy/izyan/internal/vulnerability"
)

// This file is the research lane's requested-finding boundary. The lane keeps
// its record-bound decision, decision-artifact/1 advisory binding and
// product_applicability block exactly as they are: those answer what one
// record's own bytes support. The request-level answer — attribution,
// discovery, related-record positives and the declared-corpus negative basis —
// is projected here through the one authoritative composition authority
// (finding.Project), never through a second set of composition rules.
//
// Publication re-admits rather than trusting saved data. A composition that
// the persisted record no longer re-admits is refused, not rewritten: replay
// reports policy drift instead of republishing a historical closure.

// ErrRequestCompositionUnavailable marks a request whose composition cannot be
// constructed from the records actually available. It is never repaired by
// inventing a record result, borrowing another record's facts or promoting a
// research observation into a cross-record fact.
var ErrRequestCompositionUnavailable = errors.New("research: request composition is unavailable")

// ErrRequestCompositionDrift marks a supplied composition that is not the one
// the lane's own records re-admit. A saved closure that no longer passes
// admission is reported as policy drift, never silently republished or
// silently corrected.
var ErrRequestCompositionDrift = errors.New("research: request composition differs from current admission")

// ErrRecordOnlyLane marks a request-composition call on a lane that was
// configured to stop at the record-finalization boundary.
var ErrRecordOnlyLane = errors.New("research: record-only lane owns no request composition")

// exactRecordIntake reports whether the options select the requested-finding
// contract's exact-bytes intake. Under it the frozen record's own subjects are
// the only ones an assessment may use: the alias/feed subject-merging path
// (completeAdvisoryImports) is never consulted, so a common CVE key cannot
// confer another record's package or symbol coverage.
func exactRecordIntake(o LaneOptions) bool {
	return o.RequestContract || o.RecordOnly || o.Corpus != nil
}

// RecordCase builds the lane's own record-level assessment case from the exact
// bytes it pinned. The case is not finalized: a related candidate is finalized
// with its own exact-record envelope (FinalizeRecordCase), while the primary
// record becomes the request owner inside ProjectRequestedFinding.
//
// The case carries only this record's facts — its own record pin, advisory
// bytes, applicability chain, claims, exploit model and evidence. Nothing here
// is read from another record, and no lane observation is promoted into a
// cross-record fact.
func RecordCase(lane *LaneResult) (*domain.AnalysisCase, error) {
 c,err:=recordCase(lane);if err!=nil{return nil,err};assessRecordCase(c);return c,nil
}

func recordCase(lane *LaneResult) (*domain.AnalysisCase, error) {
	if lane == nil {
		return nil, fmt.Errorf("%w: no lane record", ErrRequestCompositionUnavailable)
	}
	vuln := lane.Advisory.Vuln
	if vuln == nil {
		return nil, fmt.Errorf("%w: the lane recorded no decoded advisory record", ErrRequestCompositionUnavailable)
	}
	if lane.RecordPin == nil {
		return nil, fmt.Errorf("%w: the lane recorded no exact record pin for %q",
			ErrRequestCompositionUnavailable, vuln.ID)
	}
	recordID := strings.TrimSpace(lane.Advisory.Input.ResolvedID)
	if recordID == "" {
		recordID = strings.TrimSpace(vuln.ID)
	}
	if recordID == "" {
		return nil, fmt.Errorf("%w: the lane record carries no identity", ErrRequestCompositionUnavailable)
	}
	pin := *lane.RecordPin
	document := *vuln
	document.Scope = vuln.Scope.Clone()

	affected := scopeClone(lane.Affected)
	c := &domain.AnalysisCase{
		ID:            recordAssessmentID(pin),
		RequestedID:   recordID,
		Vulnerability: document,
		RecordPin:     &pin,
		Product:       lane.Snapshot,
		Affected:      &affected,
		Claims:        append([]domain.Claim(nil), lane.RecordClaims...),
	}
	if len(lane.Advisory.RawBytes) > 0 {
		c.AdvisoryRecord = &domain.AdvisoryRecordCapture{Pin:pin,Bytes:append([]byte(nil),lane.Advisory.RawBytes...)}
	}
	// The retained proof model is copied: a published record case may not
	// change when the lane record is mutated afterwards.
	if lane.RecordModel != nil {
		model := *lane.RecordModel
		c.Exploit = &model
	}
 if lane.RecordRootCause!=nil { raw,err:=json.Marshal(lane.RecordRootCause);if err!=nil{return nil,err};if err:=json.Unmarshal(raw,&c.RootCause);err!=nil{return nil,err} }
	c.EvidenceGraph.Version = "1"
	for _, evidence := range lane.AffectedEvidence {
		c.EvidenceGraph.AddEvidence(evidence)
	}
	for _, evidence := range lane.RecordEvidence {
		c.EvidenceGraph.AddEvidence(evidence)
	}
	if lane.Assumptions != nil {
		c.DeclaredAssumptions = lane.Assumptions
	}
	return c, nil
}

// assessRecordCase records the case's own terminal profile result through the
// one verdict authority (finding.Assess), so a saved result is always the
// classifier's own output rather than an assertion.
func assessRecordCase(c *domain.AnalysisCase) {
	build := domain.EffectiveBuildContext(c.Product)
	claims := append([]domain.Claim(nil), c.Claims...)
	var model domain.ExploitModel
	if c.Exploit != nil {
		model = *c.Exploit
	}
	var affected domain.AffectedResult
	if c.Affected != nil {
		affected = *c.Affected
	}
	result := finding.Assess(finding.AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Product:   c.Product,
			Affected:  affected,
			Model:     model,
			Claims:    claims,
			Evidence:  c.EvidenceGraph.EvidenceList(),
			RecordPin: c.RecordPin,
			AdvisoryRecord: c.AdvisoryRecord,
		},
		RootCause:     c.RootCause,
		Vulnerability: c.Vulnerability,
		Gaps:          c.AnalysisGaps,
		AssessmentID:  c.ID,
	})
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         result,
	}}
	c.AnalysisGaps = append([]domain.AnalysisGap(nil), result.Gaps...)
	c.Workflow.State = terminalStateForOutcome(result.Outcome)
}

// FinalizeRecordCase gives one independently assessed record its own
// exact-record requested-finding envelope. The envelope is about that record
// only: a child assessment's result never becomes the request's answer, and a
// child never carries a corpus boundary or a request-level attribution.
func FinalizeRecordCase(c *domain.AnalysisCase) error {
	if c == nil {
		return fmt.Errorf("%w: nil record case", ErrRequestCompositionUnavailable)
	}
	if c.RequestedID == "" {
		return fmt.Errorf("%w: record case %q carries no exact record identity",
			ErrRequestCompositionUnavailable, c.ID)
	}
	if err := finding.Finalize(c); err != nil {
		return fmt.Errorf("finalize record %q: %w", c.ID, err)
	}
	if c.Workflow.State == "" {
		c.Workflow.State = terminalStateForOutcome(c.RequestedFinding.Outcome)
	}
	return nil
}

// terminalStateForOutcome maps one published assessment outcome to the workflow
// state it terminates in: the outcome classification decides the workflow
// state, never the other way round.
func terminalStateForOutcome(outcome domain.AssessmentOutcome) domain.WorkflowState {
	switch outcome {
	case domain.OutcomeDecided:
		return domain.StateCompleted
	case domain.OutcomeExternal:
		return domain.StateInconclusive
	default:
		return domain.StateFailed
	}
}

// ProjectRequestedFinding composes the request-level answer from the lane's
// request record (identity, declared corpus, observed manifest, discovery and
// attributions) plus each independently built record assessment, and re-admits
// it through finding.Project.
//
// It delegates every composition rule: which witness may decide a profile, how
// a corpus negative basis is derived, which attributions admit, and how a
// saved envelope is compared against the current recomposition. Research adds
// no rule of its own, so the answer it publishes is the same projection JSON,
// Markdown, CLI, scan/eval, tracker, OpenVEX and CycloneDX consume.
//
// A primary that already carries an analysis-case/2 envelope is treated as a
// replay: the saved composition is re-admitted unchanged and any difference
// from the current admission is reported as policy drift. Every other primary
// is composed first, so the published value is always the re-admitted one
// rather than the caller's assertion.
func ProjectRequestedFinding(
	lane *LaneResult,
	primary *domain.AnalysisCase,
	related []domain.RelatedRecordAssessment,
) (domain.RequestedFinding, error) {
	if lane == nil {
		return domain.RequestedFinding{}, fmt.Errorf("%w: no lane record", ErrRequestCompositionUnavailable)
	}
	if primary == nil {
		return domain.RequestedFinding{}, fmt.Errorf(
			"%w: the request has no primary record assessment; research does not fabricate one",
			ErrRequestCompositionUnavailable)
	}
	root, replay, err := requestCase(lane, primary, related)
	if err != nil {
		return domain.RequestedFinding{}, err
	}
	if !replay {
		if err := finding.Finalize(root); err != nil {
			return domain.RequestedFinding{}, fmt.Errorf("compose request %q: %w",
				strings.TrimSpace(root.RequestedID), err)
		}
	}
	view, err := finding.Project(root)
	if err != nil {
		if errors.Is(err, finding.ErrPolicyDrift) {
			return domain.RequestedFinding{}, fmt.Errorf("%w: %w", ErrRequestCompositionDrift, err)
		}
		return domain.RequestedFinding{}, fmt.Errorf("%w: %w", ErrRequestCompositionUnavailable, err)
	}
	return view.Requested, nil
}

// PublishRequest composes and re-admits this lane's request answer from the
// independently assessed records the lane recorded. It is the only writer of
// LaneResult.RequestComposition, so a lane that never re-admitted a request
// never carries one.
func (l *LaneResult) PublishRequest(primary *domain.AnalysisCase) error {
	if l == nil {
		return fmt.Errorf("%w: nil lane", ErrRequestCompositionUnavailable)
	}
	if l.RecordOnly {
		return fmt.Errorf("%w: lane %q stopped at the record boundary",
			ErrRecordOnlyLane, strings.TrimSpace(l.RequestedID))
	}
	if primary == nil {
		return fmt.Errorf("%w: no primary record assessment", ErrRequestCompositionUnavailable)
	}
	root, replay, err := requestCase(l, primary, l.RelatedAssessments)
	if err != nil {
		return err
	}
	if !replay {
		if err := finding.Finalize(root); err != nil {
			return fmt.Errorf("finalize requested case: %w", err)
		}
	}
	view, err := finding.Project(root)
	if err != nil {
		if errors.Is(err, finding.ErrPolicyDrift) {
			return fmt.Errorf("%w: %w", ErrRequestCompositionDrift, err)
		}
		return fmt.Errorf("%w: %w", ErrRequestCompositionUnavailable, err)
	}
	l.RequestedCase = root
	l.RequestComposition = &view.Requested
	l.compositionAdmitted = true
	return nil
}

// AdmitRequestComposition re-admits a supplied composition against the lane's
// own re-admitted value. A lane that never composed one has nothing to compare
// against, so the supplied value is returned only when it is the lane's value.
// A different value is refused: neither the supplied one nor a rewritten one
// is published.
func (l *LaneResult) AdmitRequestComposition(want *domain.RequestedFinding) (*domain.RequestedFinding, error) {
	if l == nil || l.RequestComposition == nil || !l.compositionAdmitted {
		return nil, fmt.Errorf("%w: the lane recorded no re-admitted request composition",
			ErrRequestCompositionUnavailable)
	}
	if l.RequestedCase == nil {
		return nil, ErrRequestCompositionUnavailable
	}
	view, err := finding.Project(l.RequestedCase)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRequestCompositionDrift, err)
	}
	if !sameRequestComposition(&view.Requested, l.RequestComposition) {
		return nil, ErrRequestCompositionDrift
	}
	if want == nil {
		return l.RequestComposition, nil
	}
	if !sameRequestComposition(want, l.RequestComposition) {
		return nil, fmt.Errorf("%w: supplied composition for %q is not the lane's re-admitted composition",
			ErrRequestCompositionDrift, want.RequestedID)
	}
	return l.RequestComposition, nil
}

// requestCase assembles the request-owner case. The returned bool reports
// whether the primary already carried the saved composition (replay), in which
// case the envelope is re-admitted and never recomposed in place.
func requestCase(lane *LaneResult, primary *domain.AnalysisCase,
	related []domain.RelatedRecordAssessment) (*domain.AnalysisCase, bool, error) {
	requestedID := strings.TrimSpace(lane.RequestedID)
	if requestedID == "" {
		requestedID = strings.TrimSpace(lane.Advisory.Input.RequestedID)
	}
	if requestedID == "" {
		return nil, false, fmt.Errorf("%w: the lane carries no requested identity",
			ErrRequestCompositionUnavailable)
	}
	root := requestOwnerCase(primary)
	saved := primary.RequestedFinding
	if saved != nil {
		if primary.Schema != domain.CaseSchemaV2 {
			return nil, false, fmt.Errorf(
				"%w: assessment %q carries a requested finding without the %s discriminator",
				ErrRequestCompositionUnavailable, primary.ID, domain.CaseSchemaV2)
		}
		if strings.TrimSpace(saved.RequestedID) != requestedID {
			return nil, false, fmt.Errorf(
				"%w: assessment %q is finalized for %q and cannot be repurposed as the request %q",
				ErrRequestCompositionUnavailable, primary.ID, saved.RequestedID, requestedID)
		}
	}
	root.RequestedID = requestedID
	root.RelatedRecords = append([]domain.RelatedRecordAssessment(nil), related...)
	root.Attributions = append([]domain.CVEAttribution(nil), lane.Attributions...)
	root.CorpusDeclaration = copyDeclaration(lane.CorpusDeclaration)
	root.CorpusManifest = copyManifest(lane.CorpusManifest)
	root.RelatedDiscovery = copyDiscovery(lane.Discovery)
	if root.RelatedDiscovery != nil {
		root.RelatedDiscovery.RequestedID = requestedID
	}
	if root.Workflow.State == "" {
		root.Workflow.State = requestTerminalState(primary)
	}
	return root, saved != nil, nil
}

// requestOwnerCase builds the request-owner case from the primary record case.
//
// It assigns the record-level members field by field instead of copying the
// struct: an AnalysisCase carries an unexported mutex that guards its usage
// counters, and copying the value would duplicate lock state. The new case owns
// fresh locks and shares only the read-only record data that
// finding.Compose/finding.Project and the request composition read.
//
// The projection reads the request-level members (identity, schema, record pin,
// corpus boundary, attributions, discovery, related assessments, profile
// assessments, analysis gaps, perimeter basis) and the record members behind
// them (vulnerability, product, affected, exploit model, claims, evidence graph,
// root cause). The remaining members are carried so the request owner stays a
// faithful view of the primary record. A member added to domain.AnalysisCase
// that the projection consumes must be added here.
func requestOwnerCase(primary *domain.AnalysisCase) *domain.AnalysisCase {
	root := &domain.AnalysisCase{
		ID:                  primary.ID,
		TicketID:            primary.TicketID,
		TicketComponent:     primary.TicketComponent,
		TicketRelease:       primary.TicketRelease,
		Vulnerability:       primary.Vulnerability,
		Product:             primary.Product,
		Affected:            primary.Affected,
		RootCause:           primary.RootCause,
		Exploit:             primary.Exploit,
		Claims:              primary.Claims,
		Hypotheses:          primary.Hypotheses,
		Reviews:             primary.Reviews,
		Verdict:             primary.Verdict,
		NonLocusBasis:       primary.NonLocusBasis,
		DeclaredAssumptions: primary.DeclaredAssumptions,
		StrictLLM:           primary.StrictLLM,
		PriorCase:           primary.PriorCase,
		Workflow:            primary.Workflow,
		CVEAnalysisProfile:  primary.CVEAnalysisProfile,
		CVEAnalysisBundle:   primary.CVEAnalysisBundle,
		CVEAnalysis:         primary.CVEAnalysis,
		StrategyPlan:        primary.StrategyPlan,
		SemanticReview:      primary.SemanticReview,
		Justification:       primary.Justification,
		ContextualRisk:      primary.ContextualRisk,
		DetectedPerimeter:   primary.DetectedPerimeter,
		PerimeterRationale:  primary.PerimeterRationale,
		Profiles:            primary.Profiles,
		Schema:              primary.Schema,
		RequestedID:         primary.RequestedID,
		RecordPin:           primary.RecordPin,
  AdvisoryRecord: primary.AdvisoryRecord,
		CorpusDeclaration:   primary.CorpusDeclaration,
		CorpusManifest:      primary.CorpusManifest,
		Attributions:        primary.Attributions,
		RequestedFinding:    primary.RequestedFinding,
		RelatedDiscovery:    primary.RelatedDiscovery,
		RelatedRecords:      primary.RelatedRecords,
		ProfileAssessments:  primary.ProfileAssessments,
		AnalysisGaps:        primary.AnalysisGaps,
		PerimeterAssessment: primary.PerimeterAssessment,
	}
	root.EvidenceGraph = copyEvidenceGraph(&primary.EvidenceGraph)
	return root
}

// copyEvidenceGraph returns the graph's read-only data under a fresh lock. The
// graph carries its own unexported mutex, so the value is rebuilt instead of
// copied; slices and maps are shared because nothing on the projection path
// mutates them.
func copyEvidenceGraph(graph *domain.EvidenceGraph) domain.EvidenceGraph {
	return domain.EvidenceGraph{
		Version:          graph.Version,
		Evidence:         graph.Evidence,
		CallPaths:        graph.CallPaths,
		DataFlows:        graph.DataFlows,
		Entrypoints:      graph.Entrypoints,
		ModuleUsages:     graph.ModuleUsages,
		ModuleReachable:  graph.ModuleReachable,
		SymbolRefs:       graph.SymbolRefs,
		SymbolDecls:      graph.SymbolDecls,
		Exposures:        graph.Exposures,
		ConfigFlags:      graph.ConfigFlags,
		ConfigFieldKinds: graph.ConfigFieldKinds,
		IngressClosures:  graph.IngressClosures,
		SinkClosures:     graph.SinkClosures,
		Validations:      graph.Validations,
		Configuration:    graph.Configuration,
		Runtime:          graph.Runtime,
		ToolExecutions:   graph.ToolExecutions,
		ToolLimitations:  graph.ToolLimitations,
		Limitations:      graph.Limitations,
		Hash:             graph.Hash,
	}
}

// requestTerminalState derives the request owner's workflow state from its own
// target-actual record result. A primary with no evaluated profile is a failed
// analysis, never a completed one: the state must not manufacture progress.
func requestTerminalState(c *domain.AnalysisCase) domain.WorkflowState {
	for _, assessment := range c.ProfileAssessments {
		if assessment.IsTargetActual {
			return terminalStateForOutcome(assessment.Result.Outcome)
		}
	}
	return domain.StateFailed
}

func copyDeclaration(in *domain.CorpusDeclaration) *domain.CorpusDeclaration {
	if in == nil {
		return nil
	}
	copied := *in
	return &copied
}

func copyManifest(in *domain.CorpusManifest) *domain.CorpusManifest {
	if in == nil {
		return nil
	}
	copied := *in
	copied.Sources = append([]domain.CorpusSource(nil), in.Sources...)
	copied.Documents = append([]domain.RecordPin(nil), in.Documents...)
	copied.Problems = append([]domain.CorpusProblem(nil), in.Problems...)
	return &copied
}

func copyDiscovery(in *domain.RelatedDiscovery) *domain.RelatedDiscovery {
	if in == nil {
		return nil
	}
	copied := *in
	copied.Candidates = append([]domain.DiscoveryCandidate(nil), in.Candidates...)
	copied.Limitations = append([]string(nil), in.Limitations...)
	if in.Corpus != nil {
		corpus := *in.Corpus
		copied.Corpus = &corpus
	}
	return &copied
}

// recordAssessmentID derives a stable assessment id from the exact record
// bytes. The digest is part of the id on purpose: two different documents for
// one record id are two assessments, never one rewritten assessment.
func recordAssessmentID(pin domain.RecordPin) domain.CaseID {
	seed := pin.RecordID + "\x00" + pin.DocumentDigest
	sum := sha256.Sum256([]byte(seed))
	return domain.CaseID(sanitizeAssessmentID(pin.RecordID) + "-" + hex.EncodeToString(sum[:6]))
}

func sanitizeAssessmentID(value string) string {
	trimmed := strings.TrimSpace(value)
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, trimmed)
	if out == "" {
		return "record"
	}
	return out
}

// advisoryRecordPin pins the exact advisory bytes one record assessment was
// derived from. The pin is built only from what the loader itself measured
// (the raw-byte digest and the locator it read); a record whose bytes or id
// are missing yields no pin, and no composition may claim one.
func advisoryRecordPin(rec AdvisoryRecord) *domain.RecordPin {
	if rec.Vuln == nil || strings.TrimSpace(rec.Input.RawSHA256) == "" {
		return nil
	}
	locator := strings.TrimSpace(rec.Input.SourcePath)
	if locator == "" {
		locator = strings.TrimSpace(rec.Input.SourceKind)
	}
	pin := domain.RecordPin{
		RecordID:       rec.Vuln.ID,
		DocumentDigest: "sha256:" + rec.Input.RawSHA256,
		SourceLocator:  locator,
	}
	if rec.Input.Modified != nil {
		pin.Modified = *rec.Input.Modified
	}
	if err := pin.Validate(); err != nil {
		return nil
	}
	return &pin
}

// discoverySeed is what corpus discovery needs about the primary record: its
// exact pin and identity. Discovery never inspects the bytes' content again,
// so a primary whose content failed to resolve still seeds candidates.
func (l *LaneResult) discoverySeed(rec *AdvisoryRecord) *vulnerability.LoadedRecord {
	if rec == nil || rec.Vuln == nil {
		return nil
	}
	seed := &vulnerability.LoadedRecord{Vuln: rec.Vuln}
	if l != nil && l.RecordPin != nil {
		seed.Pin = *l.RecordPin
	}
	return seed
}

// corpusCompleteness reports what the corpus observation may claim. A partial,
// unavailable or unconfigured enumeration is recorded as partial work — never
// as complete evidence.
func corpusCompleteness(enumeration domain.DiscoveryEnumeration) evidencetools.Completeness {
	if enumeration.Complete() {
		return evidencetools.CompletenessComplete
	}
	return evidencetools.CompletenessPartial
}

// corpusObservationData is the persisted summary of one enumeration. It
// records the boundary and the counting facts; it contains no vulnerability
// claim and no document body.
func corpusObservationData(manifest domain.CorpusManifest, discovery domain.RelatedDiscovery) map[string]any {
	return map[string]any{
		"reference":   manifest.Reference,
		"captured_at": manifest.CapturedAt,
		"digest":      manifest.ObservedDigest,
		"enumeration": string(manifest.Enumeration),
		"documents":   len(manifest.Documents),
		"problems":    len(manifest.Problems),
		"sources":     len(manifest.Sources),
		"requested":   discovery.RequestedID,
		"candidates":  len(discovery.Candidates),
	}
}

// sameRequestComposition compares two compositions member by member: a
// difference anywhere is a different answer, and nothing here normalizes one
// into the other. Deep equality is used instead of a digest so an encoding
// failure can never read as "equal".
func sameRequestComposition(left, right *domain.RequestedFinding) bool {
	if left == nil || right == nil {
		return left == right
	}
	return reflect.DeepEqual(*left, *right)
}

// PersistRequestedCase writes the exact canonical case, including record and proof pins.
// It re-admits before writing; publication must never trust the cached answer.
func (l *LaneResult) PersistRequestedCase(dir string) error {
	if _, err := l.AdmitRequestComposition(nil); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(l.RequestedCase, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "requested-case.json"), raw, 0o644)
}

func requestedCaseDigest(c *domain.AnalysisCase) string {
	if c == nil {
		return ""
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validateRequestedCase(r *Report, dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "requested-case.json"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if r.RequestedCaseSHA256 == "" || hex.EncodeToString(sum[:]) != r.RequestedCaseSHA256 {
		return fmt.Errorf("canonical case digest mismatch")
	}
	var c domain.AnalysisCase
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if err := validateRequestedCaseInputs(r, &c); err != nil {
		return err
	}
	view, err := finding.Project(&c)
	if err != nil {
		return err
	}
	if !sameRequestComposition(&view.Requested, r.RequestComposition) {
		return ErrRequestCompositionDrift
	}
	if err := validateRequestedRecordBytes(&c, dir); err != nil {
		return err
	}
	return nil
}

// validateRequestedCaseInputs binds the canonical answer to the inputs named by
// the report, not merely to a matching requested ID. Use the publication's full
// snapshot projection so target and release provenance cannot drift separately
// from the snapshot/build facts. This reads retained identities only: copying a
// run directory does not require the original snapshot or advisory to exist.
func validateRequestedCaseInputs(r *Report, c *domain.AnalysisCase) error {
	var expected Report
	a := assembler{lane: &LaneResult{
		Snapshot: c.Product, SnapshotRoot: c.Product.Repository, ContentHash: c.Product.ContentHash,
	}}
	a.fillInput(&expected)
	// Compare the wire projection: omitted empty release-provenance lists can
	// decode as nil even when the publisher constructed an empty slice.
	want, err := json.Marshal(expected.Input.Snapshot)
	if err != nil {
		return err
	}
	got, err := json.Marshal(r.Input.Snapshot)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("canonical case product differs from input.snapshot")
	}
	advisory := r.Input.Advisory
	pin := domain.RecordPin{RecordID: advisory.ResolvedID, DocumentDigest: "sha256:" + advisory.RawSHA256}
	if c.RequestedID != advisory.RequestedID || c.RecordPin == nil || !c.RecordPin.Same(pin) {
		return fmt.Errorf("canonical case primary record differs from input.advisory")
	}
	return nil
}

func validateRequestedRecordBytes(c *domain.AnalysisCase, dir string) error {
	if c.RecordPin != nil {
		if err := c.RecordPin.Validate(); err != nil {
			return err
		}
		path := filepath.Join(dir, "records", strings.TrimPrefix(c.RecordPin.DocumentDigest, "sha256:")+".json")
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		record, err := vulnerability.LoadExactBytes(raw, c.RecordPin.RecordID, c.RecordPin.SourceLocator)
		if err != nil {
			return err
		}
		if !record.Pin.Same(*c.RecordPin) {
			return fmt.Errorf("persisted exact record differs from canonical pin")
		}
	}
	for _, related := range c.RelatedRecords {
		if related.Analysis == nil {
			return fmt.Errorf("related record %s has no assessment", related.ID)
		}
		if err := validateRequestedRecordBytes(related.Analysis, dir); err != nil {
			return err
		}
	}
	return nil
}

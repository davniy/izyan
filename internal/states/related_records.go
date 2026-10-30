package states

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/finding"
	"github.com/fedorovmv/izyan/internal/vulnerability"
	"github.com/fedorovmv/izyan/internal/workflow"
)

// RelatedRecordSource is the configured, pinned advisory corpus: it nominates
// candidates, reloads a nominated document's exact bytes and exposes the
// observed manifest. Discovery transfers no identity, applicability or
// exploitability authority.
type RelatedRecordSource interface {
	Discover(requestID string, primary *vulnerability.LoadedRecord) domain.RelatedDiscovery
	Document(ctx context.Context, pin domain.RecordPin) (vulnerability.LoadedRecord, error)
	Manifest() domain.CorpusManifest
}

// RecordIntake carries the exact primary record from resolution into request
// discovery and attribution. It is runtime-only; the durable proof is the
// case's RecordPin.
type RecordIntake struct {
	Record *vulnerability.LoadedRecord
}

// Set records the exact primary bytes loaded by resolution.
func (r *RecordIntake) Set(record vulnerability.LoadedRecord) {
	if r == nil {
		return
	}
	copied := record
	r.Record = &copied
}

// Get returns the exact primary bytes, or nil when resolution did not produce
// a pinned record.
func (r *RecordIntake) Get() *vulnerability.LoadedRecord {
	if r == nil {
		return nil
	}
	return r.Record
}

// RecordRunner runs one isolated record assessment. A runner must stop at the
// record-finalization boundary: it never discovers related records, composes a
// request or writes a request report.
type RecordRunner func(context.Context, *domain.AnalysisCase) error

// AttributionResolver admits the directional proposition "requested CVE C
// covers this exact record's implementation". It receives the exact record
// bytes; a resolver that cannot bind the CVE must report the unresolved
// attribution instead of guessing.
type AttributionResolver func(ctx context.Context, requestedID string, record vulnerability.LoadedRecord) ([]domain.CVEAttribution, error)

// DiscoverRecords nominates pinned candidates for the request and admits the
// primary record's directional attribution before the record pipeline runs.
// It never recursively expands `related` entries: the corpus discovery call is
// the only source of candidates.
type DiscoverRecords struct {
	// Source is the configured corpus. Nil means no corpus is configured; the
	// discovery record then carries DiscoveryNotConfigured.
	Source RelatedRecordSource
	// Intake holds the exact primary record loaded by ResolveVulnerability.
	Intake *RecordIntake
	// Attributor admits the primary record's CVE attribution. Nil leaves the
	// attribution unresolved, which composition reports only if it could
	// change the answer.
	Attributor AttributionResolver
}

func (DiscoverRecords) State() domain.WorkflowState { return domain.StateDiscoverRecords }

func (h DiscoverRecords) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	requestedID, kind, _ := domain.RequestedIdentity(c)
	if requestedID == "" {
		return workflow.Transition{}, fmt.Errorf("discover records: the request carries no identity")
	}
	if h.Source == nil {
		c.RelatedDiscovery = &domain.RelatedDiscovery{
			RequestedID: requestedID,
			Enumeration: domain.DiscoveryNotConfigured,
			Limitations: []string{
				"no advisory corpus is configured; no CVE discovery was performed",
				"a missing corpus is not evidence that no implementation is affected",
			},
		}
	} else {
		manifest := h.Source.Manifest()
		c.CorpusManifest = &manifest
		var primary *vulnerability.LoadedRecord
		if h.Intake != nil {
			primary = h.Intake.Get()
		}
		if primary == nil && c.RecordPin != nil && c.Vulnerability.ID != "" {
			// The decoded record and its own pin are sufficient for discovery
			// seeding; discovery never inspects the bytes' content again.
			primary = &vulnerability.LoadedRecord{Pin: *c.RecordPin, Vuln: &c.Vulnerability}
		}
		discovery := h.Source.Discover(requestedID, primary)
		c.RelatedDiscovery = &discovery
	}
	if h.Attributor != nil && kind == domain.ScopeCVE && h.Intake != nil {
		if record := h.Intake.Get(); record != nil {
			admitRecordAttribution(ctx, c, h.Attributor, requestedID, *record)
		}
	}
	if primaryResolved(c) {
		return workflow.Transition{Next: domain.StateCheckAffected, Reason: "request discovered; primary record available"}, nil
	}
	return workflow.Transition{
		Next:   domain.StateAssessRelatedRecords,
		Reason: "primary record unavailable; discovered candidates are still assessed",
	}, nil
}

// AssessRelatedRecords runs every nominated record through the same record
// pipeline as the primary. Each child is a fresh case built from its own
// exact bytes: no primary claims, reviews, proposals or conclusions cross the
// boundary, and children never discover further records.
type AssessRelatedRecords struct {
	Source RelatedRecordSource
	// Runner executes one isolated record assessment and stops at record
	// finalization. Nil marks every candidate unsupported.
	Runner RecordRunner
	// Attributor admits each candidate's directional CVE attribution before
	// its assessment.
	Attributor AttributionResolver
}

func (AssessRelatedRecords) State() domain.WorkflowState { return domain.StateAssessRelatedRecords }

func (h AssessRelatedRecords) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	requestedID, kind, _ := domain.RequestedIdentity(c)
	if c.RelatedDiscovery == nil {
		c.RelatedDiscovery = &domain.RelatedDiscovery{
			RequestedID: requestedID,
			Enumeration: domain.DiscoveryNotConfigured,
			Limitations: []string{"no discovery record was produced for this request"},
		}
	}
	c.RelatedDiscovery.RequestedID = requestedID
	requestEnded := analysisTruncated(c) || budgetExhausted(c)

	candidates := make([]domain.DiscoveryCandidate, 0, len(c.RelatedDiscovery.Candidates))
	for _, candidate := range c.RelatedDiscovery.Candidates {
		if c.RecordPin != nil && candidate.Record.Same(*c.RecordPin) {
			c.RelatedDiscovery.Limitations = append(c.RelatedDiscovery.Limitations, fmt.Sprintf(
				"candidate %s (%s) duplicates the primary record bytes and was not assessed a second time",
				candidate.Record.RecordID, candidate.Record.DocumentDigest))
			continue
		}
		if candidate.Disposition != domain.DispositionNotEvaluated {
			candidates = append(candidates, candidate)
			continue
		}
		switch {
		case requestEnded:
			candidate.Disposition = domain.DispositionTimedOut
			candidate.Note = "the request analysis ended before this candidate could be assessed"
		case h.Source == nil || h.Runner == nil:
			candidate.Disposition = domain.DispositionUnsupported
			candidate.Note = "no configured corpus or record runner is available to assess this candidate"
		case ctx.Err() != nil:
			candidate.Disposition = domain.DispositionTimedOut
			candidate.Note = "request context ended before this candidate could be assessed"
			requestEnded = true
		default:
			candidate = h.assess(ctx, c, candidate, kind, requestedID)
			if candidate.Disposition == domain.DispositionTimedOut || analysisTruncated(c) || budgetExhausted(c) {
				requestEnded = true
			}
		}
		candidates = append(candidates, candidate)
	}
	c.RelatedDiscovery.Candidates = candidates
	return workflow.Transition{
		Next:   domain.StateComposeRequestedFinding,
		Reason: fmt.Sprintf("assessed %d related candidate(s)", len(c.RelatedRecords)),
	}, nil
}

// assess loads one candidate's exact bytes, admits its attribution and runs
// its own record assessment. It returns the updated candidate.
func (h AssessRelatedRecords) assess(ctx context.Context, c *domain.AnalysisCase,
	candidate domain.DiscoveryCandidate, kind domain.AdvisoryScopeKind, requestedID string) domain.DiscoveryCandidate {
	record, err := h.Source.Document(ctx, candidate.Record)
	if err != nil {
		candidate.Note = err.Error()
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			candidate.Disposition = domain.DispositionTimedOut
		} else {
			candidate.Disposition = domain.DispositionLoadFailed
		}
		return candidate
	}
	if record.Vuln == nil || !record.Pin.Same(candidate.Record) || record.Vuln.ID != candidate.Record.RecordID {
		resolved := ""
		if record.Vuln != nil {
			resolved = record.Vuln.ID
		}
		candidate.Disposition = domain.DispositionAmbiguous
		candidate.Note = fmt.Sprintf("reloaded document does not match the pinned candidate bytes (resolved record %q, pin %q)",
			resolved, record.Pin.RecordID)
		return candidate
	}
	if kind == domain.ScopeCVE && h.Attributor != nil {
		admitRecordAttribution(ctx, c, h.Attributor, requestedID, record)
	}
	child, err := NewRecordCase(childCaseID(c.ID, record.Pin), record, c.Product, c.Workflow.Limits, c.UsageSnapshot())
	if err != nil {
		candidate.Disposition = domain.DispositionUnsupported
		candidate.Note = err.Error()
		return candidate
	}
	child.Workflow.Iteration = c.Workflow.Iteration
	// Operator policy inputs are shared; manual root causes, locus proposals,
	// exploit models and conclusions are not.
	child.DeclaredAssumptions = c.DeclaredAssumptions
	child.StrictLLM = c.StrictLLM
	if runErr := h.Runner(ctx, child); runErr != nil {
		candidate.Note = runErr.Error()
		if ctx.Err() != nil || errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			candidate.Disposition = domain.DispositionTimedOut
		} else {
			candidate.Disposition = domain.DispositionUnsupported
		}
	} else if child.RequestedFinding == nil {
		candidate.Disposition = domain.DispositionUnsupported
		candidate.Note = "the record runner returned without finalizing the record's requested finding"
	} else {
		candidate.Disposition = domain.DispositionEvaluated
	}
	c.RelatedRecords = append(c.RelatedRecords, domain.RelatedRecordAssessment{
		ID:       child.ID,
		Record:   record.Pin,
		Analysis: child,
	})
	// Usage is cumulative: the child started from the request's counters, so
	// writing them back leaves only the remaining request budget to the next
	// candidate. The request deadline is never extended.
	c.Workflow.Usage = child.UsageSnapshot()
	c.Workflow.Iteration = child.Workflow.Iteration
	return candidate
}

// NewRecordCase builds one isolated record assessment case from exact record
// bytes. The case is pinned to those bytes and starts at CHECK_AFFECTED: the
// product snapshot and the record identity are already supplied, so the child
// runs no snapshot, resolution or discovery state.
func NewRecordCase(
	id domain.CaseID,
	record vulnerability.LoadedRecord,
	product domain.ProductSnapshot,
	limits domain.AnalysisLimits,
	usage domain.AnalysisUsage,
) (*domain.AnalysisCase, error) {
	if id == "" {
		return nil, fmt.Errorf("record case: assessment id is required")
	}
	if record.Vuln == nil {
		return nil, fmt.Errorf("record case %q: decoded vulnerability is required", id)
	}
	if err := record.Pin.Validate(); err != nil {
		return nil, fmt.Errorf("record case %q: %w", id, err)
	}
	if record.Vuln.ID != record.Pin.RecordID {
		return nil, fmt.Errorf("record case %q: pin names record %q but the document is %q",
			id, record.Pin.RecordID, record.Vuln.ID)
	}
	now := time.Now().UTC()
	pin := record.Pin
	child := &domain.AnalysisCase{
		ID:             id,
		RequestedID:    record.Pin.RecordID,
		Vulnerability:  *record.Vuln,
		RecordPin:      &pin,
		AdvisoryRecord: advisoryRecordCapture(record),
		Product:        product,
		Workflow: domain.WorkflowStatus{
			State:     domain.StateCheckAffected,
			StartedAt: now,
			UpdatedAt: now,
			Limits:    limits,
			Usage:     usage,
		},
	}
	child.EvidenceGraph.Version = "1"
	return child, nil
}

// ComposeRequestedFinding projects the independently earned record results
// into the single authoritative requested finding. Composition is additive:
// it assigns the envelope and never rewrites the primary's applicability,
// census, claims, risk or verdict.
type ComposeRequestedFinding struct{}

func (ComposeRequestedFinding) State() domain.WorkflowState {
	return domain.StateComposeRequestedFinding
}

func (ComposeRequestedFinding) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if err := finding.Finalize(c); err != nil {
		return workflow.Transition{}, fmt.Errorf("compose requested finding: %w", err)
	}
	outcome := c.RequestedFinding.Outcome
	return workflow.Transition{
		Next:   domain.StateBuildReport,
		Reason: "requested finding composed: " + string(outcome),
	}, nil
}

// OwnIdentityAttribution admits only a record's own id/alias identity (or its
// bare related edge, reported as related_only). Publisher/CNA material needs a
// captured source and must be supplied by the configured resolver.
func OwnIdentityAttribution(_ context.Context, requestedID string, record vulnerability.LoadedRecord) ([]domain.CVEAttribution, error) {
	if record.Vuln == nil {
		return nil, fmt.Errorf("cve attribution: record has no decoded document")
	}
	attribution, err := vulnerability.AdmitAttribution(vulnerability.AttributionInput{
		CVEID:     requestedID,
		Record:    record,
		EntryRefs: RecordAttributionEntryRefs(record.Vuln),
	})
	if err != nil {
		return nil, err
	}
	return []domain.CVEAttribution{attribution}, nil
}

// RecordAttributionEntryRefs binds an attribution to the record's own affected
// entries. An inventory with explicit represented refs is authoritative; a
// record without one keeps every declared entry index.
func RecordAttributionEntryRefs(v *domain.Vulnerability) []int {
	if v == nil || v.Scope == nil || v.Scope.RecordInventory == nil {
		return nil
	}
	inventory := v.Scope.RecordInventory
	refs := append([]int(nil), inventory.RepresentedRefs...)
	if len(refs) > 0 {
		return refs
	}
	for i := range inventory.AffectedEntryCount {
		refs = append(refs, i)
	}
	return refs
}

func admitRecordAttribution(ctx context.Context, c *domain.AnalysisCase, resolver AttributionResolver,
	requestedID string, record vulnerability.LoadedRecord) {
	if resolver == nil || record.Vuln == nil || !strings.HasPrefix(strings.ToUpper(requestedID), "CVE-") {
		return
	}
	attributions, err := resolver(ctx, requestedID, record)
	if err != nil {
		c.EvidenceGraph.AddLimitation(fmt.Sprintf(
			"CVE attribution for %s (%s) is unresolved: %v", record.Pin.RecordID, requestedID, err))
		return
	}
	for _, attribution := range attributions {
		if err := attribution.Validate(); err != nil {
			c.EvidenceGraph.AddLimitation(fmt.Sprintf(
				"CVE attribution for %s (%s) failed validation: %v", record.Pin.RecordID, requestedID, err))
			continue
		}
		if !attribution.Candidate.Same(record.Pin) || !strings.EqualFold(attribution.CVEID, requestedID) {
			continue
		}
		if hasAttribution(c.Attributions, attribution.ID) {
			continue
		}
		c.Attributions = append(c.Attributions, attribution)
	}
}

func hasAttribution(attributions []domain.CVEAttribution, id string) bool {
	for _, attribution := range attributions {
		if attribution.ID == id {
			return true
		}
	}
	return false
}

func primaryResolved(c *domain.AnalysisCase) bool {
	return c != nil && c.Vulnerability.ID != ""
}

// analysisTruncated reports whether the request's analysis budget or deadline
// already ended. A truncated request cannot start a fresh candidate
// assessment: the remaining candidates stay explicitly unassessed.
func analysisTruncated(c *domain.AnalysisCase) bool {
	if c == nil {
		return true
	}
	for _, gap := range c.AnalysisGaps {
		if gap.Code == domain.GapAnalysisBudgetExhausted || gap.Code == domain.GapAnalysisTimeout {
			return true
		}
	}
	return false
}

// budgetExhausted reports whether the cumulative request counters have reached
// their configured limits. The child inherits the counters, so the next
// candidate sees only the remaining budget.
func budgetExhausted(c *domain.AnalysisCase) bool {
	if c == nil {
		return true
	}
	limits := c.Workflow.Limits
	usage := c.UsageSnapshot()
	if limits.MaxIterations > 0 && c.Workflow.Iteration >= limits.MaxIterations {
		return true
	}
	if limits.MaxToolCalls > 0 && usage.ToolCalls >= limits.MaxToolCalls {
		return true
	}
	if limits.MaxLLMCalls > 0 && usage.LLMCalls >= limits.MaxLLMCalls {
		return true
	}
	if limits.MaxSourceReads > 0 && usage.SourceReads >= limits.MaxSourceReads {
		return true
	}
	if limits.MaxReviewIterations > 0 && usage.ReviewIterations >= limits.MaxReviewIterations {
		return true
	}
	return false
}

// childCaseID derives a deterministic, filesystem-safe assessment id from the
// request id and the candidate record id. The document digest is omitted on
// purpose: one record id may only have one assessed document, and a conflicting
// version stays ambiguous rather than being assessed twice.
func childCaseID(request domain.CaseID, pin domain.RecordPin) domain.CaseID {
	root := sanitizeCaseIDPart(string(request))
	if root == "" {
		root = "request"
	}
	record := sanitizeCaseIDPart(pin.RecordID)
	if record == "" {
		record = "record"
	}
	return domain.CaseID(root + "-" + record)
}

func sanitizeCaseIDPart(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, strings.TrimSpace(value))
}

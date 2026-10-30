package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// RequestedIdentity returns the caller's request identity with the kind and
// coverage it is entitled to. The resolved advisory scope is authoritative
// when it names the same request; a primary resolution failure still leaves
// the identity on AnalysisCase.RequestedID, so discovery and composition can
// answer a CVE request whose primary record could not be loaded.
//
// A CVE request always keeps KNOWN_ONLY coverage: corpus authority travels in
// a CorpusNegativeBasis, never in the coverage field.
func RequestedIdentity(c *AnalysisCase) (string, AdvisoryScopeKind, AdvisoryCoverage) {
	if c == nil {
		return "", "", ""
	}
	var scope *AdvisoryScope
	if c.Vulnerability.Scope != nil {
		scope = c.Vulnerability.Scope
	}
	id := strings.TrimSpace(c.RequestedID)
	if id == "" && scope != nil {
		id = strings.TrimSpace(scope.RequestedID)
	}
	if id == "" {
		id = strings.TrimSpace(c.Vulnerability.ID)
	}
	kind := scopeKindFor(id)
	if scope != nil && strings.TrimSpace(scope.RequestedID) == id {
		switch scope.Kind {
		case ScopeCVE, ScopeAdvisoryEntries:
			kind = scope.Kind
		}
	}
	coverage := CoverageKnownOnly
	if kind == ScopeAdvisoryEntries && scope != nil &&
		strings.TrimSpace(scope.RequestedID) == id &&
		(scope.Coverage == CoverageComplete || scope.Coverage == CoverageKnownOnly) {
		coverage = scope.Coverage
	}
	return id, kind, coverage
}

// scopeKindFor classifies a request id without conferring any census or
// closure authority.
func scopeKindFor(id string) AdvisoryScopeKind {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-") {
		return ScopeCVE
	}
	return ScopeAdvisoryEntries
}

// ProfileAssessmentFor returns the record's own assessment for one threat
// profile. A missing profile is reported so callers can synthesize a failed
// assessment rather than borrowing another profile's result.
func ProfileAssessmentFor(c *AnalysisCase, profile ThreatProfile) (ProfileAssessment, bool) {
	if c == nil {
		return ProfileAssessment{}, false
	}
	for _, assessment := range c.ProfileAssessments {
		if assessment.Profile == profile {
			return assessment, true
		}
	}
	return ProfileAssessment{}, false
}

// Digest pins the observed corpus manifest. Documents, sources and problems
// are sorted first, so the digest is stable across enumeration order and can
// be re-derived on replay.
func (m CorpusManifest) Digest() (string, error) {
	canonical := m
	canonical.Sources = append([]CorpusSource(nil), m.Sources...)
	canonical.Documents = append([]RecordPin(nil), m.Documents...)
	canonical.Problems = append([]CorpusProblem(nil), m.Problems...)
	sort.SliceStable(canonical.Sources, func(i, j int) bool {
		left, right := canonical.Sources[i], canonical.Sources[j]
		if left.Ref != right.Ref {
			return left.Ref < right.Ref
		}
		if left.SHA256 != right.SHA256 {
			return left.SHA256 < right.SHA256
		}
		return left.CheckedAt < right.CheckedAt
	})
	sort.SliceStable(canonical.Documents, func(i, j int) bool {
		left, right := canonical.Documents[i], canonical.Documents[j]
		if left.RecordID != right.RecordID {
			return left.RecordID < right.RecordID
		}
		if left.DocumentDigest != right.DocumentDigest {
			return left.DocumentDigest < right.DocumentDigest
		}
		return left.SourceLocator < right.SourceLocator
	})
	sort.SliceStable(canonical.Problems, func(i, j int) bool {
		left, right := canonical.Problems[i], canonical.Problems[j]
		if left.Locator != right.Locator {
			return left.Locator < right.Locator
		}
		if left.RecordID != right.RecordID {
			return left.RecordID < right.RecordID
		}
		return left.Problem < right.Problem
	})
	body, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("corpus manifest %q: digest encoding failed: %w", m.Reference, err)
	}
	sum := sha256.Sum256(body)
	return recordDigestPrefix + hex.EncodeToString(sum[:]), nil
}

// Pins reports whether the observed corpus enumerated the exact document
// bytes. A nominated candidate that this manifest did not enumerate is not
// covered by the corpus boundary.
func (m CorpusManifest) Pins(pin RecordPin) bool {
	for _, document := range m.Documents {
		if document.Same(pin) {
			return true
		}
	}
	return false
}

// BuildCorpusNegativeBasis derives the Addendum-A completeness basis from the
// case's declared corpus, observed manifest, discovery record and each
// candidate's own independently earned unaffectedness result.
//
// Corpus completeness supplies the boundary, never the semantic negative: a
// candidate that is not independently NOT_AFFECTED (or whose bytes do not
// match its pin, profile or build) is rejected rather than folded into the
// basis.
func BuildCorpusNegativeBasis(c *AnalysisCase, profile ThreatProfile) (*CorpusNegativeBasis, error) {
	return declaredCorpusNegativeBasis(c, profile)
}

// AllowsDeclaredCorpusNegativeClosure reports whether the case may close a CVE
// request as NOT_AFFECTED under Addendum A. It is the typed corpus-completeness
// gate, deliberately separate from AdvisoryScope.AllowsNegativeClosure and
// insufficient on its own: every nominated candidate must also supply its own
// admitted unaffectedness proof.
func AllowsDeclaredCorpusNegativeClosure(c *AnalysisCase, profile ThreatProfile) error {
	_, err := declaredCorpusNegativeBasis(c, profile)
	return err
}

// DeclaredCorpusBoundary validates the declared corpus identity, the observed
// manifest and the discovery record's agreement, without requiring candidate
// negatives. It is the corpus-completeness half of Addendum A; semantic
// unaffectedness is a separate per-candidate obligation.
func DeclaredCorpusBoundary(c *AnalysisCase) (CorpusReference, error) {
	if c == nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: nil analysis case")
	}
	requestedID, kind, _ := RequestedIdentity(c)
	if kind != ScopeCVE {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary applies only to a CVE request, got %q", kind)
	}
	if requestedID == "" {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: requested id is required")
	}
	if c.CorpusDeclaration == nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: no operator-declared corpus is configured")
	}
	if err := c.CorpusDeclaration.Validate(); err != nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: %w", err)
	}
	if c.CorpusManifest == nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: no observed corpus manifest is recorded")
	}
	manifest := *c.CorpusManifest
	if err := manifest.Validate(); err != nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: %w", err)
	}
	declared := c.CorpusDeclaration.Pinned()
	if declared.Reference != manifest.Reference {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: declared corpus %q does not match observed corpus %q",
			declared.Reference, manifest.Reference)
	}
	if declared.Digest != manifest.ObservedDigest {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: declared digest %q does not match observed digest %q",
			declared.Digest, manifest.ObservedDigest)
	}
	if !manifest.Enumeration.Complete() {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: corpus enumeration is %q, not %q",
			manifest.Enumeration, DiscoveryFinished)
	}
	// The declared capture date is the corpus's own capture date; the
	// manifest's CapturedAt is the enumeration clock. Addendum A carries the
	// declared identity, so that date is the one the result states.
	observed := CorpusReference{
		Reference:  manifest.Reference,
		Digest:     manifest.ObservedDigest,
		CapturedAt: declared.CapturedAt,
	}
	if err := observed.Validate(); err != nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: %w", err)
	}

	discovery := c.RelatedDiscovery
	if discovery == nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: no discovery record is recorded")
	}
	if err := discovery.Validate(); err != nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: %w", err)
	}
	if discovery.RequestedID != requestedID {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: discovery requested %q, not %q",
			discovery.RequestedID, requestedID)
	}
	if !discovery.Enumeration.Complete() {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: discovery enumeration is %q, not %q",
			discovery.Enumeration, DiscoveryFinished)
	}
	if discovery.Corpus == nil {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: discovery pins no corpus identity")
	}
	if discovery.Corpus.Reference != observed.Reference ||
		discovery.Corpus.Digest != observed.Digest ||
		discovery.Corpus.CapturedAt != observed.CapturedAt {
		return CorpusReference{}, fmt.Errorf("declared corpus boundary: discovery ran against corpus %q (%s), not %q (%s)",
			discovery.Corpus.Reference, discovery.Corpus.Digest, observed.Reference, observed.Digest)
	}
	return observed, nil
}

func declaredCorpusNegativeBasis(c *AnalysisCase, profile ThreatProfile) (*CorpusNegativeBasis, error) {
	if c == nil {
		return nil, fmt.Errorf("declared corpus closure: nil analysis case")
	}
	if !profile.Known() {
		return nil, fmt.Errorf("declared corpus closure: unknown threat profile %q", profile)
	}
	observed, err := DeclaredCorpusBoundary(c)
	if err != nil {
		return nil, fmt.Errorf("declared corpus closure: %w", err)
	}
	manifest := *c.CorpusManifest
	discovery := c.RelatedDiscovery
	declared := c.CorpusDeclaration.Pinned()

	manifestDigest, err := manifest.Digest()
	if err != nil {
		return nil, fmt.Errorf("declared corpus closure: %w", err)
	}
	build := EffectiveBuildContext(c.Product)
	basis := &CorpusNegativeBasis{
		Reference:         observed.Reference,
		DeclaredDigest:    declared.Digest,
		ObservedDigest:    observed.Digest,
		CapturedAt:        observed.CapturedAt,
		Enumeration:       manifest.Enumeration,
		ManifestDigest:    manifestDigest,
		BoundaryStatement: CorpusBoundaryStatement(observed.Reference, observed.Digest, observed.CapturedAt),
	}

	// The primary record is deliberately not required here: Addendum A's
	// semantic obligation covers every nominated candidate. A primary
	// component negative supplies no closure authority, and a primary failure
	// must not veto a negative earned by independently assessed candidates
	// (the primary may describe a different record or implementation).
	assessments := make(map[RecordPin]*AnalysisCase, len(c.RelatedRecords))
	for _, related := range c.RelatedRecords {
		if related.Analysis == nil {
			continue
		}
		assessments[related.Record] = related.Analysis
	}

	for _, candidate := range discovery.Candidates {
		if candidate.Disposition != DispositionEvaluated {
			return nil, fmt.Errorf("declared corpus closure: nominated candidate %q (%s) was not independently assessed (disposition %q)",
				candidate.Record.RecordID, candidate.Record.DocumentDigest, candidate.Disposition)
		}
		if !manifest.Pins(candidate.Record) {
			return nil, fmt.Errorf("declared corpus closure: nominated candidate %q (%s) is not pinned by the observed corpus manifest",
				candidate.Record.RecordID, candidate.Record.DocumentDigest)
		}
		child := assessments[candidate.Record]
		if child == nil {
			return nil, fmt.Errorf("declared corpus closure: nominated candidate %q (%s) has no independent assessment",
				candidate.Record.RecordID, candidate.Record.DocumentDigest)
		}
		if child.RecordPin == nil || !child.RecordPin.Same(candidate.Record) {
			return nil, fmt.Errorf("declared corpus closure: candidate %q was assessed from different bytes than the corpus pin",
				candidate.Record.RecordID)
		}
		if child.Vulnerability.ID != candidate.Record.RecordID {
			return nil, fmt.Errorf("declared corpus closure: candidate %q assessment resolved record %q",
				candidate.Record.RecordID, child.Vulnerability.ID)
		}
		assessment, ok := ProfileAssessmentFor(child, profile)
		if !ok {
			return nil, fmt.Errorf("declared corpus closure: candidate %q has no %q profile assessment",
				candidate.Record.RecordID, profile)
		}
		if assessment.Result.Outcome != OutcomeDecided ||
			assessment.Result.Verdict == nil ||
			assessment.Result.Verdict.Verdict != VerdictNotAffected {
			return nil, fmt.Errorf("declared corpus closure: candidate %q did not earn an admitted %q result (%s/%q)",
				candidate.Record.RecordID, VerdictNotAffected,
				assessment.Result.Outcome, verdictOfResult(assessment.Result))
		}
		if err := assessment.Build.Matches(build); err != nil {
			return nil, fmt.Errorf("declared corpus closure: candidate %q was assessed under a different build: %w",
				candidate.Record.RecordID, err)
		}
		basis.AssessedRecords = append(basis.AssessedRecords, CorpusAssessedRecord{
			Record:  candidate.Record,
			Outcome: OutcomeDecided,
			Verdict: VerdictNotAffected,
		})
	}
	if err := basis.Validate(); err != nil {
		return nil, fmt.Errorf("declared corpus closure: %w", err)
	}
	return basis, nil
}

func verdictOfResult(result AssessmentResult) Verdict {
	if result.Verdict == nil {
		return ""
	}
	return result.Verdict.Verdict
}

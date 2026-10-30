package domain

import (
	"strings"
	"testing"
)

// closureCase is a declared, fully enumerated corpus with one independently
// assessed NOT_AFFECTED candidate. The primary record is deliberately outside
// the corpus: Addendum A closes the CVE from the corpus candidates, not from
// the primary component's own negative.
func closureCase(t *testing.T) *AnalysisCase {
	t.Helper()
	reference := testCorpusReference()
	relatedPin := testRecordPin(testRelatedID)
	manifest := CorpusManifest{
		Reference:      reference.Reference,
		CapturedAt:     reference.CapturedAt,
		ObservedDigest: reference.Digest,
		Enumeration:    DiscoveryFinished,
		Documents:      []RecordPin{relatedPin},
	}
	build := testBuildContext()
	product := ProductSnapshot{
		Repository: build.Repository,
		Commit:     build.Commit,
		GOOS:       build.GOOS,
		GOARCH:     build.GOARCH,
		GoVersion:  build.GoVersion,
	}
	child := &AnalysisCase{
		ID:            testRelatedCase,
		RequestedID:   testRelatedID,
		Vulnerability: Vulnerability{ID: testRelatedID},
		RecordPin:     &relatedPin,
		Product:       product,
		ProfileAssessments: []ProfileAssessment{{
			Profile:        ProfileZeroTrust,
			IsTargetActual: true,
			Build:          build,
			Result: AssessmentResult{
				Outcome: OutcomeDecided,
				Verdict: &VerdictResult{Verdict: VerdictNotAffected, Reason: "the gRPC implementation is not affected"},
			},
		}},
	}
	return &AnalysisCase{
		ID:          testPrimaryCase,
		RequestedID: testRequestedCVE,
		Vulnerability: Vulnerability{
			ID: testPrimaryID,
		},
		Product: product,
		CorpusDeclaration: &CorpusDeclaration{
			Reference:      reference.Reference,
			ExpectedDigest: reference.Digest,
			CapturedAt:     reference.CapturedAt,
		},
		CorpusManifest: &manifest,
		RelatedDiscovery: &RelatedDiscovery{
			RequestedID: testRequestedCVE,
			Corpus:      &reference,
			Enumeration: DiscoveryFinished,
			Candidates: []DiscoveryCandidate{{
				Record:      relatedPin,
				Edges:       []DiscoveryEdge{{Kind: RelationRelated, ID: testRequestedCVE, FromID: testRelatedID}},
				Disposition: DispositionEvaluated,
			}},
		},
		RelatedRecords: []RelatedRecordAssessment{{
			ID:       testRelatedCase,
			Record:   relatedPin,
			Analysis: child,
		}},
	}
}

func TestDeclaredCorpusClosure(t *testing.T) {
	t.Run("a complete declared corpus with independent negatives closes", func(t *testing.T) {
		c := closureCase(t)
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err != nil {
			t.Fatalf("closure: %v", err)
		}
		basis, err := BuildCorpusNegativeBasis(c, ProfileZeroTrust)
		if err != nil {
			t.Fatalf("basis: %v", err)
		}
		if err := basis.Validate(); err != nil {
			t.Fatalf("basis validation: %v", err)
		}
		reference := testCorpusReference()
		if basis.Reference != reference.Reference || basis.ObservedDigest != reference.Digest ||
			basis.CapturedAt != reference.CapturedAt {
			t.Fatalf("basis identity = %+v", basis)
		}
		if basis.DeclaredDigest != reference.Digest {
			t.Fatalf("declared digest = %q", basis.DeclaredDigest)
		}
		if basis.ManifestDigest == "" {
			t.Fatal("basis must pin the observed manifest")
		}
		if want := CorpusBoundaryStatement(reference.Reference, reference.Digest, reference.CapturedAt); basis.BoundaryStatement != want {
			t.Fatalf("boundary statement = %q, want %q", basis.BoundaryStatement, want)
		}
		if !strings.Contains(basis.BoundaryStatement, "implementations outside this corpus were not examined") {
			t.Fatalf("boundary must state the corpus limit: %q", basis.BoundaryStatement)
		}
		if len(basis.AssessedRecords) != 1 || !basis.AssessedRecords[0].Record.Same(testRecordPin(testRelatedID)) {
			t.Fatalf("assessed records = %+v", basis.AssessedRecords)
		}
		if err := basis.CoversDiscoveredCandidates(c.RelatedDiscovery); err != nil {
			t.Fatalf("candidate coverage: %v", err)
		}
	})

	t.Run("an empty declared corpus states the bounded no-match result", func(t *testing.T) {
		c := closureCase(t)
		c.RelatedDiscovery.Candidates = nil
		c.RelatedRecords = nil
		basis, err := BuildCorpusNegativeBasis(c, ProfileZeroTrust)
		if err != nil {
			t.Fatalf("empty declared corpus: %v", err)
		}
		if len(basis.AssessedRecords) != 0 {
			t.Fatalf("assessed records = %+v", basis.AssessedRecords)
		}
		if !strings.Contains(basis.BoundaryStatement, "implementations outside this corpus were not examined") {
			t.Fatal("the no-match result must keep the corpus boundary")
		}
	})

	t.Run("no declaration can close a CVE", func(t *testing.T) {
		c := closureCase(t)
		c.CorpusDeclaration = nil
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "no operator-declared corpus") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("declared and observed digests must agree", func(t *testing.T) {
		c := closureCase(t)
		c.CorpusDeclaration.ExpectedDigest = testDigest("other corpus")
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "declared digest") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("a partial enumeration cannot ground a negative", func(t *testing.T) {
		c := closureCase(t)
		c.CorpusManifest.Enumeration = DiscoveryPartial
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "enumeration") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("an unassessed candidate blocks closure", func(t *testing.T) {
		c := closureCase(t)
		c.RelatedDiscovery.Candidates[0].Disposition = DispositionNotEvaluated
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "not independently assessed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("a candidate without its own assessment blocks closure", func(t *testing.T) {
		c := closureCase(t)
		c.RelatedRecords = nil
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "no independent assessment") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("a failed candidate is never a negative", func(t *testing.T) {
		c := closureCase(t)
		child := c.RelatedRecords[0].Analysis
		child.ProfileAssessments[0].Result = AssessmentResult{
			Outcome: OutcomeFailed,
			Gaps: []AnalysisGap{{
				Owner: GapOwnerCode, Code: GapReachabilityProofIncomplete,
				Obligation: ObligationCondition, AssessmentID: testRelatedCase, Message: "proof incomplete",
			}},
		}
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "did not earn an admitted") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("NEPF is not relabelled NOT_AFFECTED", func(t *testing.T) {
		c := closureCase(t)
		c.RelatedRecords[0].Analysis.ProfileAssessments[0].Result.Verdict.Verdict = VerdictNoExploitPathFound
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil {
			t.Fatal("NEPF must not close a corpus negative")
		}
	})

	t.Run("a different build cannot ground this corpus negative", func(t *testing.T) {
		c := closureCase(t)
		build := testBuildContext()
		build.GOARCH = "arm64"
		c.RelatedRecords[0].Analysis.ProfileAssessments[0].Build = build
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "different build") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("a candidate must be pinned by the observed corpus", func(t *testing.T) {
		c := closureCase(t)
		c.CorpusManifest.Documents = []RecordPin{testRecordPin("GO-OTHER")}
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "not pinned by the observed corpus") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("the declared capture date is authoritative over the enumeration clock", func(t *testing.T) {
		c := closureCase(t)
		c.CorpusManifest.CapturedAt = "2026-10-27T00:00:00Z"
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err != nil {
			t.Fatalf("closure must use the declared capture date: %v", err)
		}
		basis, err := BuildCorpusNegativeBasis(c, ProfileZeroTrust)
		if err != nil {
			t.Fatalf("basis: %v", err)
		}
		if want := testCorpusReference().CapturedAt; basis.CapturedAt != want {
			t.Fatalf("basis captured date = %q, want the declared %q", basis.CapturedAt, want)
		}
		if want := CorpusBoundaryStatement(basis.Reference, basis.ObservedDigest, basis.CapturedAt); basis.BoundaryStatement != want {
			t.Fatalf("boundary = %q, want %q", basis.BoundaryStatement, want)
		}
	})

	t.Run("the primary component negative is not required", func(t *testing.T) {
		c := closureCase(t)
		c.AnalysisGaps = []AnalysisGap{{
			Owner: GapOwnerScope, Code: GapUnsupportedNegativeScope,
			Obligation: ObligationNegativeScope, AssessmentID: testPrimaryCase,
			Message: "the 22-entry component negative cannot close the CVE",
		}}
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err != nil {
			t.Fatalf("closure must not require the primary's own negative: %v", err)
		}
	})

	t.Run("an exact request is not a CVE-wide corpus question", func(t *testing.T) {
		c := closureCase(t)
		c.RequestedID = testPrimaryID
		c.Vulnerability.Scope = &AdvisoryScope{
			RequestedID: testPrimaryID, ResolvedID: testPrimaryID,
			Kind: ScopeAdvisoryEntries, Coverage: CoverageComplete,
		}
		if err := AllowsDeclaredCorpusNegativeClosure(c, ProfileZeroTrust); err == nil ||
			!strings.Contains(err.Error(), "only to a CVE request") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCorpusManifestDigest(t *testing.T) {
	first := testRecordPin("GO-2023-2153")
	second := testRecordPin("GO-2024-2512")
	left := CorpusManifest{
		Reference:      "osv-dump",
		CapturedAt:     "2026-10-20",
		ObservedDigest: testDigest("corpus"),
		Enumeration:    DiscoveryFinished,
		Documents:      []RecordPin{second, first},
		Sources: []CorpusSource{
			{Ref: "corpus/b.zip", SHA256: "b"},
			{Ref: "corpus/a.zip", SHA256: "a"},
		},
	}
	right := left
	right.Documents = []RecordPin{first, second}
	right.Sources = []CorpusSource{
		{Ref: "corpus/a.zip", SHA256: "a"},
		{Ref: "corpus/b.zip", SHA256: "b"},
	}
	leftDigest, err := left.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := right.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("manifest digest depends on enumeration order: %s != %s", leftDigest, rightDigest)
	}
	if leftDigest == "" || !strings.HasPrefix(leftDigest, "sha256:") {
		t.Fatalf("manifest digest = %q", leftDigest)
	}
	if !left.Pins(first) || left.Pins(testRecordPin("GO-9999-9999")) {
		t.Fatal("manifest pin membership is wrong")
	}
}

func TestRequestedIdentity(t *testing.T) {
	t.Run("a CVE request keeps known-only coverage", func(t *testing.T) {
		c := &AnalysisCase{
			RequestedID: testRequestedCVE,
			Vulnerability: Vulnerability{
				ID: testPrimaryID,
				Scope: &AdvisoryScope{
					RequestedID: testRequestedCVE, ResolvedID: testPrimaryID,
					Kind: ScopeCVE, Coverage: CoverageComplete,
				},
			},
		}
		id, kind, coverage := RequestedIdentity(c)
		if id != testRequestedCVE || kind != ScopeCVE || coverage != CoverageKnownOnly {
			t.Fatalf("identity = %q/%q/%q", id, kind, coverage)
		}
	})

	t.Run("an exact request keeps its own complete coverage", func(t *testing.T) {
		c := &AnalysisCase{
			RequestedID: testPrimaryID,
			Vulnerability: Vulnerability{
				ID: testPrimaryID,
				Scope: &AdvisoryScope{
					RequestedID: testPrimaryID, ResolvedID: testPrimaryID,
					Kind: ScopeAdvisoryEntries, Coverage: CoverageComplete,
				},
			},
		}
		id, kind, coverage := RequestedIdentity(c)
		if id != testPrimaryID || kind != ScopeAdvisoryEntries || coverage != CoverageComplete {
			t.Fatalf("identity = %q/%q/%q", id, kind, coverage)
		}
	})

	t.Run("a resolution failure still carries the request identity", func(t *testing.T) {
		c := &AnalysisCase{RequestedID: testRequestedCVE}
		id, kind, coverage := RequestedIdentity(c)
		if id != testRequestedCVE || kind != ScopeCVE || coverage != CoverageKnownOnly {
			t.Fatalf("identity = %q/%q/%q", id, kind, coverage)
		}
	})
}

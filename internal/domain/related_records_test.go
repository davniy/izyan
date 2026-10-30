package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func testCorpusReference() CorpusReference {
	return CorpusReference{
		Reference:  "osv-dump-2026-10-20",
		Digest:     testDigest("corpus bytes"),
		CapturedAt: "2026-10-20",
	}
}

func testDiscoveryCandidate(recordID string, kind RelationKind, via string, disposition CandidateDisposition) DiscoveryCandidate {
	return DiscoveryCandidate{
		Record:      testRecordPin(recordID),
		Edges:       []DiscoveryEdge{{Kind: kind, ID: via, FromID: recordID}},
		Disposition: disposition,
	}
}

// testRelatedDiscovery is the inverse-lookup case: GO-2023-2153 names
// CVE-2023-44487 in its own related field, so the CVE lookup reaches it without
// any outgoing edge from the requested record.
func testRelatedDiscovery(candidates ...DiscoveryCandidate) RelatedDiscovery {
	corpus := testCorpusReference()
	if len(candidates) == 0 {
		candidates = []DiscoveryCandidate{
			testDiscoveryCandidate(testRelatedID, RelationRelated, testRequestedCVE, DispositionEvaluated),
		}
	}
	return RelatedDiscovery{
		RequestedID: testRequestedCVE,
		Corpus:      &corpus,
		Enumeration: DiscoveryFinished,
		Candidates:  candidates,
		Limitations: []string{"discovery ran only against the configured corpus"},
	}
}

func testCorpusNegativeBasis() CorpusNegativeBasis {
	corpus := testCorpusReference()
	return CorpusNegativeBasis{
		Reference:      corpus.Reference,
		DeclaredDigest: corpus.Digest,
		ObservedDigest: corpus.Digest,
		CapturedAt:     corpus.CapturedAt,
		Enumeration:    DiscoveryFinished,
		ManifestDigest: testDigest("manifest"),
		AssessedRecords: []CorpusAssessedRecord{
			{Record: testRecordPin(testRelatedID), Outcome: OutcomeDecided, Verdict: VerdictNotAffected},
		},
		BoundaryStatement: CorpusBoundaryStatement(corpus.Reference, corpus.Digest, corpus.CapturedAt),
	}
}

func testPublisherAttribution() CVEAttribution {
	return CVEAttribution{
		ID:                "ATTR-GO-2023-2153",
		CVEID:             testRequestedCVE,
		Candidate:         testRecordPin(testRelatedID),
		EntryRefs:         []int{0},
		MechanismID:       "rapid-reset",
		Basis:             AttributionPublisher,
		SourceURI:         "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
		CapturedDigest:    testDigest("publisher advisory bytes"),
		SourceField:       "aliases[0]",
		SourceQuote:       "CVE-2023-44487",
		PublisherAdvisory: "GHSA-m425-mq94-257g",
		Module:            "google.golang.org/grpc",
		Repository:        "github.com/grpc/grpc-go",
		FixRefs:           []string{"https://github.com/grpc/grpc-go/pull/6703"},
		Admission:         AttributionAdmitted,
	}
}

func TestRelatedRecordSchema(t *testing.T) {
	t.Run("discovery enumerations are the frozen lowercase values", func(t *testing.T) {
		want := map[DiscoveryEnumeration]string{
			DiscoveryFinished:      "finished",
			DiscoveryPartial:       "partial",
			DiscoveryUnavailable:   "unavailable",
			DiscoveryNotConfigured: "not_configured",
		}
		for value, text := range want {
			if string(value) != text {
				t.Fatalf("enumeration = %q, want %q", value, text)
			}
			if !value.Valid() {
				t.Fatalf("%q must be valid", value)
			}
			if string(value) != strings.ToLower(text) {
				t.Fatalf("%q is not lowercase", value)
			}
		}
		if !DiscoveryFinished.Complete() {
			t.Fatal("finished must be the only complete enumeration")
		}
		if DiscoveryEnumeration("FINISHED").Valid() || DiscoveryPartial.Complete() {
			t.Fatal("unknown enumerations must be rejected and only finished may be complete")
		}
	})

	t.Run("candidate dispositions are the frozen lowercase values", func(t *testing.T) {
		want := map[CandidateDisposition]string{
			DispositionEvaluated:    "evaluated",
			DispositionUnsupported:  "unsupported",
			DispositionAmbiguous:    "ambiguous",
			DispositionLoadFailed:   "load_failed",
			DispositionTimedOut:     "timed_out",
			DispositionNotEvaluated: "not_evaluated",
		}
		for value, text := range want {
			if string(value) != text {
				t.Fatalf("disposition = %q, want %q", value, text)
			}
			if !value.Valid() {
				t.Fatalf("%q must be valid", value)
			}
			if value.Resolved() != (value == DispositionEvaluated) {
				t.Fatalf("%q resolved=%v", value, value.Resolved())
			}
		}
		if CandidateDisposition("PENDING").Valid() {
			t.Fatal("unknown dispositions must be rejected")
		}
	})

	t.Run("relation kinds keep discovery separate", func(t *testing.T) {
		for _, kind := range []RelationKind{RelationRecord, RelationAlias, RelationRelated} {
			if !kind.Valid() {
				t.Fatalf("%q must be valid", kind)
			}
		}
		if RelationKind("alias+related").Valid() {
			t.Fatal("a merged relation kind must be rejected")
		}
	})

	t.Run("related discovery records candidates but claims no identity", func(t *testing.T) {
		discovery := testRelatedDiscovery()
		if err := discovery.Validate(); err != nil {
			t.Fatalf("related discovery: %v", err)
		}
		body := mustJSON(t, discovery)
		for _, want := range []string{
			`"requested_id":"CVE-2023-44487"`,
			`"enumeration":"finished"`,
			`"kind":"related"`,
			`"disposition":"evaluated"`,
			`"document_digest":"sha256:`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("discovery body lacks %s:\n%s", want, body)
			}
		}

		var round RelatedDiscovery
		if err := json.Unmarshal([]byte(body), &round); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if err := round.Validate(); err != nil {
			t.Fatalf("round-tripped discovery: %v", err)
		}
	})

	t.Run("malformed discovery is rejected", func(t *testing.T) {
		finishedWithoutCorpus := testRelatedDiscovery()
		finishedWithoutCorpus.Corpus = nil
		mustFail(t, finishedWithoutCorpus.Validate(), "requires the pinned corpus reference")

		unknownEnumeration := testRelatedDiscovery()
		unknownEnumeration.Enumeration = "MOSTLY_DONE"
		mustFail(t, unknownEnumeration.Validate(), "unknown enumeration outcome")

		noRequestedID := testRelatedDiscovery()
		noRequestedID.RequestedID = ""
		mustFail(t, noRequestedID.Validate(), "requested id is required")

		noEdges := testRelatedDiscovery()
		noEdges.Candidates[0].Edges = nil
		mustFail(t, noEdges.Validate(), "at least one nominating relationship is required")

		unknownDisposition := testRelatedDiscovery()
		unknownDisposition.Candidates[0].Disposition = "assessed"
		mustFail(t, unknownDisposition.Validate(), "unknown disposition")

		duplicate := testRelatedDiscovery()
		duplicate.Candidates = append(duplicate.Candidates, duplicate.Candidates[0])
		mustFail(t, duplicate.Validate(), "is listed twice")

		noCorpusReference := testRelatedDiscovery()
		noCorpusReference.Corpus = &CorpusReference{Reference: "osv"}
		mustFail(t, noCorpusReference.Validate(), "corpus reference")
	})

	t.Run("conflicting bytes for one record id stay distinct candidates", func(t *testing.T) {
		first := testDiscoveryCandidate(testRelatedID, RelationRelated, testRequestedCVE, DispositionAmbiguous)
		conflicting := first
		conflicting.Record.DocumentDigest = testDigest("conflicting bytes")
		conflicting.Disposition = DispositionAmbiguous

		discovery := testRelatedDiscovery(first, conflicting)
		if err := discovery.Validate(); err != nil {
			t.Fatalf("conflicting candidates: %v", err)
		}
		if discovery.Candidates[0].Record.Same(discovery.Candidates[1].Record) {
			t.Fatal("conflicting byte sets are not the same document")
		}
	})

	t.Run("corpus manifest cannot claim a partial enumeration as finished", func(t *testing.T) {
		manifest := CorpusManifest{
			Reference:      "osv-dump-2026-10-20",
			CapturedAt:     "2026-10-20",
			ObservedDigest: testDigest("corpus bytes"),
			Enumeration:    DiscoveryFinished,
			Documents:      []RecordPin{testRecordPin(testRelatedID)},
			Problems:       []CorpusProblem{{Locator: "GO-2023-2153.json", Problem: "decode failed"}},
		}
		mustFail(t, manifest.Validate(), "cannot carry")

		manifest.Problems = nil
		if err := manifest.Validate(); err != nil {
			t.Fatalf("finished manifest: %v", err)
		}

		manifest.Documents = nil
		mustFail(t, manifest.Validate(), "must pin the enumerated documents")

		partial := manifest
		partial.Enumeration = DiscoveryPartial
		partial.Problems = []CorpusProblem{{Locator: "broken.json", Problem: "decode failed"}}
		if err := partial.Validate(); err != nil {
			t.Fatalf("partial manifest: %v", err)
		}

		unknown := manifest
		unknown.Enumeration = "done"
		mustFail(t, unknown.Validate(), "unknown enumeration outcome")

		emptyProblem := manifest
		emptyProblem.Problems = []CorpusProblem{{Locator: "broken.json"}}
		mustFail(t, emptyProblem.Validate(), "no problem text")
	})

	t.Run("corpus declaration pins the declared boundary", func(t *testing.T) {
		declaration := CorpusDeclaration{
			Reference:      "osv-dump-2026-10-20",
			ExpectedDigest: testDigest("corpus bytes"),
			CapturedAt:     "2026-10-20",
		}
		if err := declaration.Validate(); err != nil {
			t.Fatalf("corpus declaration: %v", err)
		}
		if got := declaration.Pinned(); got.Digest != declaration.ExpectedDigest || got.Reference != declaration.Reference {
			t.Fatalf("declaration pins %+v", got)
		}

		badDigest := declaration
		badDigest.ExpectedDigest = "sha256:short"
		mustFail(t, badDigest.Validate(), "lowercase 64-hex sha256 digest")

		noDate := declaration
		noDate.CapturedAt = ""
		mustFail(t, noDate.Validate(), "capture date is required")
	})

	t.Run("publisher attribution requires the captured material", func(t *testing.T) {
		attribution := testPublisherAttribution()
		if err := attribution.Validate(); err != nil {
			t.Fatalf("publisher attribution: %v", err)
		}
		if !attribution.Admitted() {
			t.Fatal("fixture attribution must be admitted")
		}

		cases := []struct {
			name   string
			mutate func(*CVEAttribution)
			want   string
		}{
			{"no source uri", func(a *CVEAttribution) { a.SourceURI = "" }, "captured source URI"},
			{"no captured digest", func(a *CVEAttribution) { a.CapturedDigest = "" }, "is not a sha256:"},
			{"no exact field", func(a *CVEAttribution) { a.SourceField = "" }, "exact source field"},
			{"no exact quote", func(a *CVEAttribution) { a.SourceQuote = "" }, "exact source quote"},
			{"no publisher advisory", func(a *CVEAttribution) { a.PublisherAdvisory = "" }, "publisher advisory identity"},
			{"no implementation binding", func(a *CVEAttribution) {
				a.Module = ""
				a.Repository = ""
			}, "covered module or repository"},
			{"no fix binding", func(a *CVEAttribution) { a.FixRefs = nil }, "fix reference"},
			{"no covered entry or mechanism", func(a *CVEAttribution) {
				a.EntryRefs = nil
				a.MechanismID = ""
			}, "must bind a covered entry or mechanism"},
			{"unordered entry refs", func(a *CVEAttribution) { a.EntryRefs = []int{2, 1} }, "not strictly ordered"},
			{"unknown basis", func(a *CVEAttribution) { a.Basis = "blog" }, "unknown attribution basis"},
			{"unknown admission", func(a *CVEAttribution) { a.Admission = "maybe" }, "unknown admission"},
			{"no cve id", func(a *CVEAttribution) { a.CVEID = "" }, "cve id is required"},
			{"bad candidate pin", func(a *CVEAttribution) { a.Candidate.SourceLocator = "" }, "source locator is required"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				attribution := testPublisherAttribution()
				tc.mutate(&attribution)
				mustFail(t, attribution.Validate(), tc.want)
			})
		}
	})

	t.Run("own id and alias bases need no captured material", func(t *testing.T) {
		ownID := CVEAttribution{
			ID:        "ATTR-OWN",
			CVEID:     testRequestedCVE,
			Candidate: testRecordPin(testRequestedCVE),
			Basis:     AttributionOwnID,
			Admission: AttributionAdmitted,
		}
		// own_id carries the CVE as its own record id, so an entry or
		// mechanism binding is still required.
		mustFail(t, ownID.Validate(), "must bind a covered entry or mechanism")
		ownID.EntryRefs = []int{0}
		if err := ownID.Validate(); err != nil {
			t.Fatalf("own_id attribution: %v", err)
		}

		ambiguous := ownID
		ambiguous.Basis = AttributionOwnAlias
		ambiguous.Admission = AttributionAmbiguous
		if err := ambiguous.Validate(); err != nil {
			t.Fatalf("ambiguous own_alias attribution: %v", err)
		}
	})

	t.Run("a bare related edge can only be related_only", func(t *testing.T) {
		related := CVEAttribution{
			ID:        "ATTR-RELATED-ONLY",
			CVEID:     testRequestedCVE,
			Candidate: testRecordPin(testRelatedID),
			Admission: AttributionRelatedOnly,
		}
		if err := related.Validate(); err != nil {
			t.Fatalf("related_only attribution: %v", err)
		}
		if related.Admitted() {
			t.Fatal("related_only must not be admitted")
		}

		withBasis := related
		withBasis.Basis = AttributionPublisher
		mustFail(t, withBasis.Validate(), "carries no attribution basis")
	})

	t.Run("declared corpus basis closes only when every part is present", func(t *testing.T) {
		basis := testCorpusNegativeBasis()
		if err := basis.Validate(); err != nil {
			t.Fatalf("corpus negative basis: %v", err)
		}
		if !basis.AllowsDeclaredCorpusClosure() {
			t.Fatal("a complete declared basis must close")
		}
		if !strings.Contains(basis.BoundaryStatement,
			"implementations outside this corpus were not examined") {
			t.Fatalf("boundary statement %q must state the corpus limit", basis.BoundaryStatement)
		}

		var absent *CorpusNegativeBasis
		mustFail(t, absent.Validate(), "nil basis")
		if absent.AllowsDeclaredCorpusClosure() {
			t.Fatal("a nil basis can never close")
		}
	})

	t.Run("corpus basis rejects every incomplete part", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*CorpusNegativeBasis)
			want   string
		}{
			{"digest mismatch", func(b *CorpusNegativeBasis) {
				b.ObservedDigest = testDigest("other corpus")
			}, "declared digest"},
			{"partial enumeration", func(b *CorpusNegativeBasis) {
				b.Enumeration = DiscoveryPartial
			}, "cannot ground a CVE-wide negative"},
			{"undeclared enumeration", func(b *CorpusNegativeBasis) {
				b.Enumeration = DiscoveryNotConfigured
			}, "cannot ground a CVE-wide negative"},
			{"unknown enumeration", func(b *CorpusNegativeBasis) {
				b.Enumeration = "eventually"
			}, "unknown enumeration outcome"},
			{"no manifest digest", func(b *CorpusNegativeBasis) {
				b.ManifestDigest = ""
			}, "manifest digest"},
			{"no capture date", func(b *CorpusNegativeBasis) {
				b.CapturedAt = ""
			}, "capture date is required"},
			{"paraphrased boundary", func(b *CorpusNegativeBasis) {
				b.BoundaryStatement = "we looked at everything"
			}, "must be carried verbatim"},
			{"child never affected path", func(b *CorpusNegativeBasis) {
				b.AssessedRecords = []CorpusAssessedRecord{{
					Record:  testRecordPin(testRelatedID),
					Outcome: OutcomeDecided,
					Verdict: VerdictNoExploitPathFound,
				}}
			}, "a corpus negative needs admitted unaffectedness"},
			{"child failed", func(b *CorpusNegativeBasis) {
				b.AssessedRecords = []CorpusAssessedRecord{{
					Record:  testRecordPin(testRelatedID),
					Outcome: OutcomeFailed,
				}}
			}, "cannot contribute a corpus negative"},
			{"child external", func(b *CorpusNegativeBasis) {
				b.AssessedRecords = []CorpusAssessedRecord{{
					Record:  testRecordPin(testRelatedID),
					Outcome: OutcomeExternal,
				}}
			}, "cannot contribute a corpus negative"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				basis := testCorpusNegativeBasis()
				tc.mutate(&basis)
				mustFail(t, basis.Validate(), tc.want)
				if basis.AllowsDeclaredCorpusClosure() {
					t.Fatal("an incomplete basis must not close")
				}
			})
		}
	})

	t.Run("corpus closure covers every nominated candidate", func(t *testing.T) {
		basis := testCorpusNegativeBasis()
		discovery := testRelatedDiscovery()
		if err := basis.CoversDiscoveredCandidates(&discovery); err != nil {
			t.Fatalf("covered discovery: %v", err)
		}

		uncovered := testRelatedDiscovery(
			testDiscoveryCandidate(testRelatedID, RelationRelated, testRequestedCVE, DispositionEvaluated),
			testDiscoveryCandidate("GO-2023-9999", RelationAlias, testRequestedCVE, DispositionTimedOut),
		)
		mustFail(t, basis.CoversDiscoveredCandidates(&uncovered),
			"has no independently assessed unaffectedness result")

		otherCorpus := testCorpusReference()
		otherCorpus.Reference = "other-corpus"
		otherCorpus.Digest = testDigest("other corpus bytes")
		mismatched := testRelatedDiscovery()
		mismatched.Corpus = &otherCorpus
		mustFail(t, basis.CoversDiscoveredCandidates(&mismatched), "not this basis")

		mustFail(t, basis.CoversDiscoveredCandidates(nil), "discovery record is required")
	})

	t.Run("a declared empty corpus states a bounded result only", func(t *testing.T) {
		basis := testCorpusNegativeBasis()
		basis.AssessedRecords = nil
		if err := basis.Validate(); err != nil {
			t.Fatalf("bounded empty basis: %v", err)
		}
		empty := testRelatedDiscovery()
		empty.Candidates = nil
		if err := basis.CoversDiscoveredCandidates(&empty); err != nil {
			t.Fatalf("no nominated candidates: %v", err)
		}
	})
}

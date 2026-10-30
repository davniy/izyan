package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Shared fixtures for the outcome, requested-finding and related-record
// contract tests. Everything is built from unexported package helpers so the
// tests exercise the same digests and pins the producers will.

const (
	testPrimaryCase  CaseID = "case-primary"
	testRelatedCase  CaseID = "case-related-grpc"
	testRequestedCVE        = "CVE-2023-44487"
	testPrimaryID           = "GHSA-qppj-fm5r-hxr3"
	testRelatedID           = "GO-2023-2153"
)

// testDigest builds a well-formed sha256:<lowercase hex> digest, so a fixture
// can never accidentally pass because a literal happened to be 64 hex chars.
func testDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return recordDigestPrefix + hex.EncodeToString(sum[:])
}

func testRecordPin(recordID string) RecordPin {
	return RecordPin{
		RecordID:       recordID,
		DocumentDigest: testDigest(recordID),
		SourceLocator:  "corpus/" + recordID + ".json",
		Modified:       "2026-10-20T00:00:00Z",
	}
}

func testBuildContext() BuildContext {
	return BuildContext{
		Repository: "github.com/kubernetes/kubernetes",
		Commit:     "e196d24",
		GOOS:       "linux",
		GOARCH:     "amd64",
		GoVersion:  "go1.25.0",
	}
}

func testQualifiedRef(assessmentID CaseID, ref string) QualifiedRef {
	return QualifiedRef{AssessmentID: assessmentID, Ref: ref}
}

// testExternalDependency is a complete, evidence-bound deployment fact: the
// artifact cannot supply it and two legitimate environments answer differently.
func testExternalDependency(assessmentID CaseID) ExternalDependency {
	return ExternalDependency{
		MissingFact:        "whether an unprivileged pod can connect to the kubelet podresources Unix socket",
		AffectedObligation: ObligationCondition,
		BoundaryEvidenceRefs: []QualifiedRef{
			testQualifiedRef(assessmentID, "EV-socket-binding"),
		},
		WhyArtifactCannotSupply: "socket ownership and pod placement are deployment facts, not source facts",
		AlternativesChanging: []string{
			"an unprivileged neighbour pod can connect, so the transport is hostile-reachable",
			"only a privileged host-network client can connect, so the transport is not adversary-reachable",
		},
		ResolvingEvidence: "the rendered kubelet securityContext, socket mode and the cluster pod-to-pod policy",
	}
}

func testGap(assessmentID CaseID, owner GapOwner, code GapCode, obligation Obligation) AnalysisGap {
	gap := AnalysisGap{
		Owner:        owner,
		Code:         code,
		Obligation:   obligation,
		AssessmentID: assessmentID,
		Message:      "fixture gap",
	}
	if owner == GapOwnerExternal {
		dependency := testExternalDependency(assessmentID)
		gap.External = &dependency
	}
	return gap
}

func testInconclusiveVerdict() *VerdictResult {
	return &VerdictResult{Verdict: VerdictInconclusive, Reason: "fixture external dependency"}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(encoded)
}

func mustFail(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

func TestAssessmentOutcome(t *testing.T) {
	t.Run("decided accepts only the three definitive verdicts", func(t *testing.T) {
		for _, verdict := range []Verdict{VerdictExploitable, VerdictNotAffected, VerdictNoExploitPathFound} {
			result := AssessmentResult{
				Outcome: OutcomeDecided,
				Verdict: &VerdictResult{Verdict: verdict, Reason: "fixture"},
			}
			if err := result.Validate(); err != nil {
				t.Fatalf("DECIDED %q: %v", verdict, err)
			}
		}
	})

	t.Run("external dependency is inconclusive plus complete dependencies", func(t *testing.T) {
		result := AssessmentResult{
			Outcome:              OutcomeExternal,
			Verdict:              testInconclusiveVerdict(),
			ExternalDependencies: []ExternalDependency{testExternalDependency(testRelatedCase)},
			Gaps:                 []AnalysisGap{testGap(testRelatedCase, GapOwnerExternal, GapExternalDependencyUnresolved, ObligationCondition)},
		}
		if err := result.Validate(); err != nil {
			t.Fatalf("EXTERNAL_DEPENDENCY: %v", err)
		}
	})

	t.Run("failed publishes no verdict but must explain itself", func(t *testing.T) {
		result := AssessmentResult{
			Outcome: OutcomeFailed,
			Gaps: []AnalysisGap{
				testGap(testRelatedCase, GapOwnerProof, GapTriggerProofIncomplete, ObligationCondition),
			},
			Limitations: []string{"an unrelated supporting unknown does not change this failure"},
		}
		if err := result.Validate(); err != nil {
			t.Fatalf("FAILED: %v", err)
		}
	})

	t.Run("malformed results are rejected", func(t *testing.T) {
		cases := []struct {
			name   string
			result AssessmentResult
			want   string
		}{
			{
				name:   "decided without verdict",
				result: AssessmentResult{Outcome: OutcomeDecided},
				want:   "requires a verdict",
			},
			{
				name: "decided with inconclusive",
				result: AssessmentResult{
					Outcome: OutcomeDecided,
					Verdict: testInconclusiveVerdict(),
				},
				want: "is not definitive",
			},
			{
				name: "decided retaining an external dependency",
				result: AssessmentResult{
					Outcome:              OutcomeDecided,
					Verdict:              &VerdictResult{Verdict: VerdictExploitable, Reason: "fixture"},
					ExternalDependencies: []ExternalDependency{testExternalDependency(testRelatedCase)},
				},
				want: "must not publish external dependencies",
			},
			{
				name: "decided retaining an unresolved external gap",
				result: AssessmentResult{
					Outcome: OutcomeDecided,
					Verdict: &VerdictResult{Verdict: VerdictExploitable, Reason: "fixture"},
					Gaps:    []AnalysisGap{testGap(testRelatedCase, GapOwnerExternal, GapExternalDependencyUnresolved, ObligationCondition)},
				},
				want: "retains an unresolved EXTERNAL gap",
			},
			{
				name: "external with a definitive verdict",
				result: AssessmentResult{
					Outcome:              OutcomeExternal,
					Verdict:              &VerdictResult{Verdict: VerdictExploitable, Reason: "fixture"},
					ExternalDependencies: []ExternalDependency{testExternalDependency(testRelatedCase)},
				},
				want: `must be "INCONCLUSIVE"`,
			},
			{
				name: "external without any dependency",
				result: AssessmentResult{
					Outcome: OutcomeExternal,
					Verdict: testInconclusiveVerdict(),
				},
				want: "requires at least one external dependency",
			},
			{
				name: "external mixed with an analyzer-owned blocker",
				result: AssessmentResult{
					Outcome:              OutcomeExternal,
					Verdict:              testInconclusiveVerdict(),
					ExternalDependencies: []ExternalDependency{testExternalDependency(testRelatedCase)},
					Gaps:                 []AnalysisGap{testGap(testRelatedCase, GapOwnerProof, GapReviewUnresolved, ObligationCondition)},
				},
				want: "mixed blockers must fail",
			},
			{
				name: "failed carrying a verdict",
				result: AssessmentResult{
					Outcome: OutcomeFailed,
					Verdict: testInconclusiveVerdict(),
					Gaps:    []AnalysisGap{testGap(testRelatedCase, GapOwnerProof, GapReviewUnresolved, ObligationCondition)},
				},
				want: "must not publish a verdict",
			},
			{
				name:   "failed without any typed gap",
				result: AssessmentResult{Outcome: OutcomeFailed},
				want:   "requires at least one typed analysis gap",
			},
			{
				name: "failed carrying external dependencies",
				result: AssessmentResult{
					Outcome:              OutcomeFailed,
					Gaps:                 []AnalysisGap{testGap(testRelatedCase, GapOwnerProof, GapReviewUnresolved, ObligationCondition)},
					ExternalDependencies: []ExternalDependency{testExternalDependency(testRelatedCase)},
				},
				want: "must not publish external dependencies",
			},
			{
				name:   "unknown outcome",
				result: AssessmentResult{Outcome: "PROBABLY_FINE"},
				want:   "unknown outcome",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mustFail(t, tc.result.Validate(), tc.want)
			})
		}
	})

	t.Run("external dependency must be fully evidence-bound", func(t *testing.T) {
		incomplete := testExternalDependency(testRelatedCase)
		incomplete.ResolvingEvidence = ""
		result := AssessmentResult{
			Outcome:              OutcomeExternal,
			Verdict:              testInconclusiveVerdict(),
			ExternalDependencies: []ExternalDependency{incomplete},
		}
		mustFail(t, result.Validate(), "resolving evidence is required")

		unbound := testExternalDependency(testRelatedCase)
		unbound.BoundaryEvidenceRefs = []QualifiedRef{{Ref: "EV-socket-binding"}}
		result.ExternalDependencies = []ExternalDependency{unbound}
		mustFail(t, result.Validate(), "assessment id is required")
	})

	t.Run("gaps are typed and coupled to their owner", func(t *testing.T) {
		accepted := testGap(testPrimaryCase, GapOwnerCode, GapMeasurementNotCompleted, ObligationMeasurement)
		if err := accepted.Validate(); err != nil {
			t.Fatalf("code gap: %v", err)
		}

		cases := []struct {
			name string
			gap  AnalysisGap
			want string
		}{
			{
				name: "unknown owner",
				gap:  AnalysisGap{Owner: "MAYBE", Code: GapReviewUnresolved, Obligation: ObligationCondition, AssessmentID: testPrimaryCase, Message: "m"},
				want: "unknown gap owner",
			},
			{
				name: "unknown code",
				gap:  AnalysisGap{Owner: GapOwnerCode, Code: "SOMETHING_ELSE", Obligation: ObligationCondition, AssessmentID: testPrimaryCase, Message: "m"},
				want: "unknown gap code",
			},
			{
				name: "unknown obligation",
				gap:  AnalysisGap{Owner: GapOwnerCode, Code: GapReviewUnresolved, Obligation: "VIBES", AssessmentID: testPrimaryCase, Message: "m"},
				want: "unknown obligation",
			},
			{
				name: "unbound assessment",
				gap:  AnalysisGap{Owner: GapOwnerCode, Code: GapReviewUnresolved, Obligation: ObligationCondition, Message: "m"},
				want: "assessment id is required",
			},
			{
				name: "missing message",
				gap:  AnalysisGap{Owner: GapOwnerCode, Code: GapReviewUnresolved, Obligation: ObligationCondition, AssessmentID: testPrimaryCase},
				want: "message is required",
			},
			{
				name: "external without a dependency",
				gap: AnalysisGap{
					Owner: GapOwnerExternal, Code: GapExternalDependencyUnresolved,
					Obligation: ObligationCondition, AssessmentID: testPrimaryCase, Message: "m",
				},
				want: "requires an external dependency",
			},
			{
				name: "external reusing an analyzer-owned code",
				gap: AnalysisGap{
					Owner: GapOwnerExternal, Code: GapReviewUnresolved,
					Obligation: ObligationCondition, AssessmentID: testPrimaryCase, Message: "m",
				},
				want: "EXTERNAL owner must carry",
			},
			{
				name: "analyzer-owned gap smuggling an external dependency",
				gap: func() AnalysisGap {
					gap := testGap(testPrimaryCase, GapOwnerCode, GapReviewUnresolved, ObligationCondition)
					dependency := testExternalDependency(testPrimaryCase)
					gap.External = &dependency
					return gap
				}(),
				want: "only the EXTERNAL owner may carry an external dependency",
			},
			{
				name: "unbound evidence reference",
				gap: AnalysisGap{
					Owner: GapOwnerCode, Code: GapReviewUnresolved, Obligation: ObligationCondition,
					AssessmentID: testPrimaryCase, Message: "m",
					EvidenceRefs: []QualifiedRef{{Ref: "EV-1"}},
				},
				want: "assessment id is required",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mustFail(t, tc.gap.Validate(), tc.want)
			})
		}
	})

	t.Run("profile assessments carry their own claims and result", func(t *testing.T) {
		valid := ProfileAssessment{
			Profile:        ProfileZeroTrust,
			IsTargetActual: true,
			Build:          testBuildContext(),
			Claims: []Claim{
				{
					ID:           "CL-C1",
					ConditionID:  "C1",
					Result:       ClaimTrue,
					ControlBasis: ControlBasisTransportPeerInput,
				},
			},
			Result: AssessmentResult{
				Outcome: OutcomeDecided,
				Verdict: &VerdictResult{Verdict: VerdictExploitable, Reason: "fixture"},
			},
		}
		if err := valid.Validate(); err != nil {
			t.Fatalf("profile assessment: %v", err)
		}

		unknownProfile := valid
		unknownProfile.Profile = "trusted_lan"
		mustFail(t, unknownProfile.Validate(), "unknown threat profile")

		badClaimGap := valid
		badClaimGap.Claims = []Claim{{ID: "CL-C1", AnalysisGaps: []AnalysisGap{{Owner: GapOwnerCode}}}}
		mustFail(t, badClaimGap.Validate(), "analysis gap")

		badResult := valid
		badResult.Result = AssessmentResult{Outcome: OutcomeFailed}
		mustFail(t, badResult.Validate(), "requires at least one typed analysis gap")
	})

	t.Run("outcomes serialize with a stable discriminator", func(t *testing.T) {
		decided := AssessmentResult{
			Outcome: OutcomeDecided,
			Verdict: &VerdictResult{Verdict: VerdictExploitable, Reason: "fixture"},
		}
		body := mustJSON(t, decided)
		for _, want := range []string{`"assessment_outcome":"DECIDED"`, `"verdict":{"verdict":"EXPLOITABLE"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("decided body %s lacks %s", body, want)
			}
		}

		failed := AssessmentResult{
			Outcome: OutcomeFailed,
			Gaps:    []AnalysisGap{testGap(testPrimaryCase, GapOwnerProof, GapReviewUnresolved, ObligationCondition)},
		}
		body = mustJSON(t, failed)
		if strings.Contains(body, `"verdict"`) {
			t.Fatalf("failed body must omit the verdict: %s", body)
		}
		if !strings.Contains(body, `"assessment_outcome":"FAILED"`) {
			t.Fatalf("failed body lacks its outcome: %s", body)
		}

		external := AssessmentResult{
			Outcome:              OutcomeExternal,
			Verdict:              testInconclusiveVerdict(),
			ExternalDependencies: []ExternalDependency{testExternalDependency(testRelatedCase)},
		}
		var round AssessmentResult
		if err := json.Unmarshal([]byte(mustJSON(t, external)), &round); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if err := round.Validate(); err != nil {
			t.Fatalf("round-tripped external result: %v", err)
		}
		if round.ExternalDependencies[0].MissingFact != external.ExternalDependencies[0].MissingFact {
			t.Fatalf("round trip lost the missing fact: %+v", round.ExternalDependencies[0])
		}
	})

	t.Run("schema discriminator is frozen", func(t *testing.T) {
		if CaseSchemaV2 != "analysis-case/2" {
			t.Fatalf("schema = %q, want analysis-case/2", CaseSchemaV2)
		}
		if !CaseSchemaV2.Valid() {
			t.Fatal("analysis-case/2 must be a valid schema")
		}
		if CaseResultSchema("analysis-case/3").Valid() {
			t.Fatal("an unknown schema must not validate")
		}
		if FindingPending != "PENDING" || FindingFinal != "FINAL" {
			t.Fatalf("finding statuses = %q/%q", FindingPending, FindingFinal)
		}
	})

	t.Run("record pins bind the exact document bytes", func(t *testing.T) {
		pin := testRecordPin(testRelatedID)
		if err := pin.Validate(); err != nil {
			t.Fatalf("record pin: %v", err)
		}
		if !pin.Same(testRecordPin(testRelatedID)) {
			t.Fatal("identical pins must be the same document")
		}
		other := testRecordPin(testRelatedID)
		other.DocumentDigest = testDigest("other bytes")
		if pin.Same(other) {
			t.Fatal("conflicting bytes for one record id must not be the same document")
		}

		badDigest := pin
		badDigest.DocumentDigest = "sha256:NOTHEX"
		mustFail(t, badDigest.Validate(), "not a lowercase 64-hex sha256 digest")

		bareDigest := pin
		bareDigest.DocumentDigest = strings.TrimPrefix(pin.DocumentDigest, recordDigestPrefix)
		mustFail(t, bareDigest.Validate(), "is not a sha256:sha256 digest")

		noLocator := pin
		noLocator.SourceLocator = ""
		mustFail(t, noLocator.Validate(), "source locator is required")
	})

	t.Run("case result requires the v2 envelope but reads legacy cases", func(t *testing.T) {
		legacy := &AnalysisCase{ID: testPrimaryCase}
		if err := legacy.ValidateCaseResult(); err != nil {
			t.Fatalf("legacy case: %v", err)
		}

		missing := &AnalysisCase{ID: testPrimaryCase, Schema: CaseSchemaV2}
		mustFail(t, missing.ValidateCaseResult(), "requires a requested_finding envelope")

		enveloped := &AnalysisCase{
			ID:               testPrimaryCase,
			Schema:           CaseSchemaV2,
			RecordPin:        func() *RecordPin { pin := testRecordPin(testPrimaryID); return &pin }(),
			RequestedFinding: func() *RequestedFinding { finding := testPendingRequestedFinding(); return &finding }(),
		}
		if err := enveloped.ValidateCaseResult(); err != nil {
			t.Fatalf("v2 case: %v", err)
		}

		badPin := &AnalysisCase{
			ID:     testPrimaryCase,
			Schema: CaseSchemaV2,
			RecordPin: &RecordPin{
				RecordID:       testPrimaryID,
				DocumentDigest: "sha256:abc",
				SourceLocator:  "corpus/GHSA-qppj-fm5r-hxr3.json",
			},
			RequestedFinding: func() *RequestedFinding { finding := testPendingRequestedFinding(); return &finding }(),
		}
		mustFail(t, badPin.ValidateCaseResult(), "sha256 digest")
	})
}

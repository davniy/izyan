package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func testPendingRequestedFinding() RequestedFinding {
	return RequestedFinding{
		Status:              FindingPending,
		RequestedID:         testPrimaryID,
		RequestedKind:       ScopeAdvisoryEntries,
		Coverage:            CoverageComplete,
		PrimaryAssessmentID: testPrimaryCase,
	}
}

// testProofOrigin is the gRPC witness shape: a related record's own entry and
// mechanism, proved under one profile and build, with qualified references.
func testProofOrigin() ProofOrigin {
	return ProofOrigin{
		AssessmentID:  testRelatedCase,
		Record:        testRecordPin(testRelatedID),
		EntryRefs:     []int{0},
		MechanismID:   "rapid-reset",
		AttributionID: "ATTR-GO-2023-2153",
		Profile:       ProfileZeroTrust,
		Build:         testBuildContext(),
		ConditionRefs: []QualifiedRef{testQualifiedRef(testRelatedCase, "C-TRIGGER")},
		ClaimRefs:     []QualifiedRef{testQualifiedRef(testRelatedCase, "CL-C-TRIGGER")},
		EvidenceRefs:  []QualifiedRef{testQualifiedRef(testRelatedCase, "EV-trigger")},
	}
}

func testExploitableProfile() FindingProfile {
	return FindingProfile{
		Profile:             ProfileZeroTrust,
		IsTargetActual:      true,
		Build:               testBuildContext(),
		Outcome:             OutcomeDecided,
		Verdict:             VerdictExploitable,
		Reason:              "rooted server transport consumes peer frames before the fixed handler quota",
		ExploitabilityScope: ScopeTransportPeer,
		ProofOrigins:        []ProofOrigin{testProofOrigin()},
		Limitations:         TransportPeerScopeLimitations(),
	}
}

func testCVERequestedFinding(profile FindingProfile) RequestedFinding {
	return RequestedFinding{
		Status:              FindingFinal,
		RequestedID:         testRequestedCVE,
		RequestedKind:       ScopeCVE,
		Coverage:            CoverageKnownOnly,
		PrimaryAssessmentID: testPrimaryCase,
		FindingProfile:      profile,
	}
}

func testExternalProfile() FindingProfile {
	return FindingProfile{
		Profile:              ProfileZeroTrust,
		IsTargetActual:       true,
		Build:                testBuildContext(),
		Outcome:              OutcomeExternal,
		Verdict:              VerdictInconclusive,
		Reason:               "deployed socket access is not supplied",
		ExternalDependencies: []ExternalDependency{testExternalDependency(testRelatedCase)},
		Gaps:                 []AnalysisGap{testGap(testRelatedCase, GapOwnerExternal, GapExternalDependencyUnresolved, ObligationCondition)},
	}
}

func TestRequestedFindingSchema(t *testing.T) {
	t.Run("transport-peer positive carries origin, scope and mandatory limitation", func(t *testing.T) {
		profile := testExploitableProfile()
		if err := profile.Validate(); err != nil {
			t.Fatalf("exploitable profile: %v", err)
		}
		finding := testCVERequestedFinding(profile)
		if err := finding.Validate(); err != nil {
			t.Fatalf("cve exploitable finding: %v", err)
		}

		body := mustJSON(t, finding)
		for _, want := range []string{
			`"status":"FINAL"`,
			`"requested_id":"CVE-2023-44487"`,
			`"requested_kind":"CVE"`,
			`"coverage":"KNOWN_ONLY"`,
			`"assessment_outcome":"DECIDED"`,
			`"verdict":"EXPLOITABLE"`,
			`"exploitability_scope":"transport-peer"`,
			`"record":{"record_id":"GO-2023-2153"`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("finding body lacks %s:\n%s", want, body)
			}
		}
		if !strings.Contains(body, TransportPeerScopeLimitation) {
			t.Fatalf("finding body lacks the mandatory transport-peer limitation:\n%s", body)
		}

		var round RequestedFinding
		if err := json.Unmarshal([]byte(body), &round); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if err := round.Validate(); err != nil {
			t.Fatalf("round-tripped finding: %v", err)
		}
	})

	t.Run("a positive without a witness is rejected", func(t *testing.T) {
		profile := testExploitableProfile()
		profile.ProofOrigins = nil
		mustFail(t, profile.Validate(), "requires at least one proof origin")
	})

	t.Run("a scope requires its mandatory limitation", func(t *testing.T) {
		profile := testExploitableProfile()
		profile.Limitations = nil
		mustFail(t, profile.Validate(), "requires the mandatory limitation")

		library := testExploitableProfile()
		library.ExploitabilityScope = ScopeLibraryAPI
		mustFail(t, library.Validate(), "requires the mandatory limitation")
	})

	t.Run("a scope only scopes a positive", func(t *testing.T) {
		profile := testExploitableProfile()
		profile.Verdict = VerdictNotAffected
		mustFail(t, profile.Validate(), `requires an "EXPLOITABLE" verdict`)
	})

	t.Run("scope and profile enums are closed", func(t *testing.T) {
		profile := testExploitableProfile()
		profile.ExploitabilityScope = "internet-facing"
		mustFail(t, profile.Validate(), "unknown exploitability scope")

		profile = testExploitableProfile()
		profile.Profile = "trusted_network"
		mustFail(t, profile.Validate(), "unknown threat profile")

		profile = testExploitableProfile()
		profile.Verdict = "PROBABLY_EXPLOITABLE"
		mustFail(t, profile.Validate(), "unknown verdict")
	})

	t.Run("proof origins are bound, attributed and evidence-bearing", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*ProofOrigin)
			want   string
		}{
			{"no assessment", func(o *ProofOrigin) { o.AssessmentID = "" }, "assessment id is required"},
			{"no record pin", func(o *ProofOrigin) { o.Record = RecordPin{} }, "record pin"},
			{"no covered entry or mechanism", func(o *ProofOrigin) {
				o.EntryRefs = nil
				o.MechanismID = ""
			}, "a covered entry or mechanism is required"},
			{"no evidence", func(o *ProofOrigin) { o.EvidenceRefs = nil }, "at least one evidence reference is required"},
			{"unbound claim reference", func(o *ProofOrigin) {
				o.ClaimRefs = []QualifiedRef{{Ref: "CL-C-TRIGGER"}}
			}, "assessment id is required"},
			{"unordered entry refs", func(o *ProofOrigin) { o.EntryRefs = []int{1, 1} }, "not strictly ordered"},
			{"unknown profile", func(o *ProofOrigin) { o.Profile = "trusted_lan" }, "unknown threat profile"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				origin := testProofOrigin()
				tc.mutate(&origin)
				mustFail(t, origin.Validate(), tc.want)
			})
		}

		profile := testExploitableProfile()
		otherProfileOrigin := testProofOrigin()
		otherProfileOrigin.Profile = ProfileClusterPerimeter
		profile.ProofOrigins = append(profile.ProofOrigins, otherProfileOrigin)
		mustFail(t, profile.Validate(), "origin profile")
	})

	t.Run("external dependency result is inconclusive and evidence-bound", func(t *testing.T) {
		profile := testExternalProfile()
		if err := profile.Validate(); err != nil {
			t.Fatalf("external profile: %v", err)
		}
		if !strings.Contains(mustJSON(t, profile), `"verdict":"INCONCLUSIVE"`) {
			t.Fatal("external profile must publish INCONCLUSIVE")
		}

		missingDependency := testExternalProfile()
		missingDependency.ExternalDependencies = nil
		mustFail(t, missingDependency.Validate(), "requires at least one external dependency")

		mixedBlocker := testExternalProfile()
		mixedBlocker.Gaps = []AnalysisGap{testGap(testRelatedCase, GapOwnerCode, GapReachabilityProofIncomplete, ObligationCondition)}
		mustFail(t, mixedBlocker.Validate(), "mixed blockers must fail")
	})

	t.Run("failed result publishes no verdict but keeps its diagnostics", func(t *testing.T) {
		profile := FindingProfile{
			Profile:        ProfileZeroTrust,
			IsTargetActual: true,
			Build:          testBuildContext(),
			Outcome:        OutcomeFailed,
			Reason:         "the trigger mechanism could not be proved",
			Gaps:           []AnalysisGap{testGap(testRelatedCase, GapOwnerProof, GapTriggerProofIncomplete, ObligationCondition)},
		}
		if err := profile.Validate(); err != nil {
			t.Fatalf("failed profile: %v", err)
		}
		body := mustJSON(t, profile)
		if strings.Contains(body, `"verdict"`) {
			t.Fatalf("failed profile must omit its verdict: %s", body)
		}

		withVerdict := profile
		withVerdict.Verdict = VerdictInconclusive
		mustFail(t, withVerdict.Validate(), "must not publish a verdict")

		withoutGaps := profile
		withoutGaps.Gaps = nil
		mustFail(t, withoutGaps.Validate(), "requires at least one typed analysis gap")
	})

	t.Run("a pending envelope claims nothing", func(t *testing.T) {
		finding := testPendingRequestedFinding()
		if err := finding.Validate(); err != nil {
			t.Fatalf("pending finding: %v", err)
		}
		body := mustJSON(t, finding)
		if !strings.Contains(body, `"status":"PENDING"`) {
			t.Fatalf("pending body lacks its status: %s", body)
		}
		var wire map[string]any
		if err := json.Unmarshal([]byte(body), &wire); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if claimed, ok := wire["assessment_outcome"]; ok && claimed != "" {
			t.Fatalf("pending envelope must not claim an outcome, got %v", claimed)
		}
		if claimed, ok := wire["verdict"]; ok {
			t.Fatalf("pending envelope must not claim a verdict, got %v", claimed)
		}

		claimed := testPendingRequestedFinding()
		claimed.Outcome = OutcomeDecided
		mustFail(t, claimed.Validate(), "PENDING is a persistence phase")

		claimed = testPendingRequestedFinding()
		claimed.Verdict = VerdictExploitable
		mustFail(t, claimed.Validate(), "PENDING is a persistence phase")
	})

	t.Run("cve coverage stays known-only because corpus authority travels separately", func(t *testing.T) {
		finding := testCVERequestedFinding(testExploitableProfile())
		finding.Coverage = CoverageComplete
		mustFail(t, finding.Validate(), `a CVE request keeps "KNOWN_ONLY" coverage`)
	})

	t.Run("cve-wide negative requires the declared corpus basis", func(t *testing.T) {
		profile := FindingProfile{
			Profile:        ProfileZeroTrust,
			IsTargetActual: true,
			Build:          testBuildContext(),
			Outcome:        OutcomeDecided,
			Verdict:        VerdictNotAffected,
			Reason:         "no candidate in the declared corpus is affected",
		}
		finding := testCVERequestedFinding(profile)
		if err := profile.Validate(); err != nil {
			t.Fatalf("profile without corpus rule: %v", err)
		}
		mustFail(t, finding.Validate(), "requires a declared corpus negative basis")

		basis := testCorpusNegativeBasis()
		profile.CorpusNegativeBasis = &basis
		finding.FindingProfile = profile
		if err := finding.Validate(); err != nil {
			t.Fatalf("declared corpus negative: %v", err)
		}
	})

	t.Run("a corpus basis cannot ride on a non-negative verdict", func(t *testing.T) {
		profile := testExploitableProfile()
		basis := testCorpusNegativeBasis()
		profile.CorpusNegativeBasis = &basis
		mustFail(t, profile.Validate(), `a corpus negative basis requires an "NOT_AFFECTED" verdict`)
	})

	t.Run("an exact negative does not need corpus authority", func(t *testing.T) {
		finding := RequestedFinding{
			Status:              FindingFinal,
			RequestedID:         testPrimaryID,
			RequestedKind:       ScopeAdvisoryEntries,
			Coverage:            CoverageComplete,
			PrimaryAssessmentID: testPrimaryCase,
			FindingProfile: FindingProfile{
				Profile:        ProfileZeroTrust,
				IsTargetActual: true,
				Build:          testBuildContext(),
				Outcome:        OutcomeDecided,
				Verdict:        VerdictNotAffected,
				Reason:         "the recorded build resolves outside this record's own affected ranges",
			},
		}
		if err := finding.Validate(); err != nil {
			t.Fatalf("exact negative: %v", err)
		}
	})

	t.Run("the profile set may not contradict the requested result", func(t *testing.T) {
		finding := testCVERequestedFinding(testExploitableProfile())

		hypothetical := testExploitableProfile()
		hypothetical.Profile = ProfileClusterPerimeter
		hypothetical.IsTargetActual = false
		hypothetical.Verdict = VerdictNotAffected
		hypothetical.ExploitabilityScope = ""
		hypothetical.ProofOrigins = nil
		hypothetical.Reason = "hypothetical cluster-perimeter premise, not the deployment answer"
		finding.Profiles = []FindingProfile{hypothetical}
		if err := finding.Validate(); err != nil {
			t.Fatalf("hypothetical profile set: %v", err)
		}

		contradicting := hypothetical
		contradicting.IsTargetActual = true
		finding.Profiles = []FindingProfile{contradicting}
		mustFail(t, finding.Validate(), "disagrees with the requested result")

		finding.FindingProfile.IsTargetActual = false
		finding.Profiles = []FindingProfile{testExploitableProfile()}
		mustFail(t, finding.Validate(), "but the requested result is not marked actual")
	})

	t.Run("envelope enums and identity are closed", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*RequestedFinding)
			want   string
		}{
			{"unknown status", func(f *RequestedFinding) { f.Status = "DRAFT" }, "unknown status"},
			{"no requested id", func(f *RequestedFinding) { f.RequestedID = "" }, "requested id is required"},
			{"unknown kind", func(f *RequestedFinding) { f.RequestedKind = "ADVISORY" }, "unknown requested kind"},
			{"unknown coverage", func(f *RequestedFinding) { f.Coverage = "SOME" }, "unknown coverage"},
			{"no primary assessment", func(f *RequestedFinding) { f.PrimaryAssessmentID = "" }, "primary assessment id is required"},
			{"no reason", func(f *RequestedFinding) { f.Reason = "" }, "reason is required"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				finding := testCVERequestedFinding(testExploitableProfile())
				tc.mutate(&finding)
				mustFail(t, finding.Validate(), tc.want)
			})
		}
	})

	t.Run("related record assessments keep identity and pinned bytes", func(t *testing.T) {
		assessment := RelatedRecordAssessment{ID: testRelatedCase, Record: testRecordPin(testRelatedID)}
		if err := assessment.Validate(); err != nil {
			t.Fatalf("related record assessment: %v", err)
		}
		mustFail(t, RelatedRecordAssessment{Record: testRecordPin(testRelatedID)}.Validate(), "assessment id is required")
		mustFail(t, RelatedRecordAssessment{ID: testRelatedCase}.Validate(), "record pin")
	})
}

package finding_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/finding"
)

const (
	composeCVE         = "CVE-2023-44487"
	composePrimary     = "GHSA-qppj-fm5r-hxr3"
	composeGRPC        = "GO-2023-2153"
	composeOther       = "GO-2024-2512"
	composePrimaryCase = domain.CaseID("case-primary")
	composeGRPCCase    = domain.CaseID("case-grpc")
	composeOtherCase   = domain.CaseID("case-other")
)

func composeDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func composePin(id string) domain.RecordPin {
	return domain.RecordPin{
		RecordID:       id,
		DocumentDigest: composeDigest(id),
		SourceLocator:  "corpus/" + id + ".json",
	}
}

func composeBuild() domain.BuildContext {
	return domain.BuildContext{
		Repository: "github.com/kubernetes/kubernetes",
		Commit:     "e196d24",
		GOOS:       "linux",
		GOARCH:     "amd64",
		GoVersion:  "go1.25.0",
	}
}

func composeProduct(build domain.BuildContext) domain.ProductSnapshot {
	return domain.ProductSnapshot{
		Repository: build.Repository,
		Commit:     build.Commit,
		GOOS:       build.GOOS,
		GOARCH:     build.GOARCH,
		GoVersion:  build.GoVersion,
	}
}

func composeScope(requestedID string, kind domain.AdvisoryScopeKind, coverage domain.AdvisoryCoverage) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: requestedID,
		ResolvedID:  requestedID,
		Kind:        kind,
		Coverage:    coverage,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         requestedID,
			DocumentDigest:     composeDigest(requestedID),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go"}},
			RepresentedRefs:    []int{0},
		},
	}
}

func composeProfile(profile domain.ThreatProfile, actual bool, build domain.BuildContext,
	result domain.AssessmentResult) domain.ProfileAssessment {
	return domain.ProfileAssessment{
		Profile:        profile,
		IsTargetActual: actual,
		Build:          build,
		Result:         result,
	}
}

func composeExploitable(scope domain.ExploitabilityScope) domain.AssessmentResult {
	return domain.AssessmentResult{
		Outcome: domain.OutcomeDecided,
		Verdict: &domain.VerdictResult{
			Verdict:             domain.VerdictExploitable,
			Reason:              "rooted transport witness",
			ConditionIDs:        []domain.ConditionID{"C-TRIGGER"},
			EvidenceIDs:         []domain.EvidenceID{"EV-TRIGGER"},
			ExploitabilityScope: scope,
		},
	}
}

func composeNotAffected() domain.AssessmentResult {
	return domain.AssessmentResult{
		Outcome: domain.OutcomeDecided,
		Verdict: &domain.VerdictResult{Verdict: domain.VerdictNotAffected, Reason: "not affected"},
	}
}

func composeFailed(id domain.CaseID, code domain.GapCode) domain.AssessmentResult {
	return domain.AssessmentResult{
		Outcome: domain.OutcomeFailed,
		Gaps: []domain.AnalysisGap{{
			Owner:        domain.GapOwnerProof,
			Code:         code,
			Obligation:   domain.ObligationCondition,
			AssessmentID: id,
			Message:      "proof did not complete",
		}},
	}
}

func composeExternal(id domain.CaseID) domain.AssessmentResult {
	dependency := domain.ExternalDependency{
		MissingFact:             "the shipped gRPC version is not recorded",
		AffectedObligation:      domain.ObligationVersionRange,
		BoundaryEvidenceRefs:    []domain.QualifiedRef{{AssessmentID: id, Ref: "EV-VERSION"}},
		WhyArtifactCannotSupply: "the artifact records no release toolchain or module lock",
		AlternativesChanging:    []string{"v1.55.0 is affected", "v1.56.3 is fixed"},
		ResolvingEvidence:       "the shipped binary's build info",
	}
	return domain.AssessmentResult{
		Outcome:              domain.OutcomeExternal,
		Verdict:              &domain.VerdictResult{Verdict: domain.VerdictInconclusive, Reason: "version unknown"},
		ExternalDependencies: []domain.ExternalDependency{dependency},
		Gaps: []domain.AnalysisGap{{
			Owner:        domain.GapOwnerExternal,
			Code:         domain.GapExternalDependencyUnresolved,
			Obligation:   domain.ObligationVersionRange,
			AssessmentID: id,
			Message:      "version unknown",
			External:     &dependency,
		}},
	}
}

func composeAttribution(id string, pin domain.RecordPin) domain.CVEAttribution {
	return domain.CVEAttribution{
		ID:                id,
		CVEID:             composeCVE,
		Candidate:         pin,
		EntryRefs:         []int{0},
		MechanismID:       "http2-rapid-reset",
		Basis:             domain.AttributionPublisher,
		SourceURI:         "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
		CapturedDigest:    composeDigest("a"),
		SourceField:       "cve_ids[0]",
		SourceQuote:       composeCVE,
		PublisherAdvisory: "GHSA-m425-mq94-257g",
		Module:            "google.golang.org/grpc",
		Repository:        "github.com/grpc/grpc-go",
		FixRefs:           []string{"https://github.com/grpc/grpc-go/pull/6703"},
		Admission:         domain.AttributionAdmitted,
	}
}

func exactPrimaryCase() *domain.AnalysisCase {
	build := composeBuild()
	pin := composePin(composePrimary)
	return &domain.AnalysisCase{
		ID:            composePrimaryCase,
		RequestedID:   composePrimary,
		Vulnerability: domain.Vulnerability{ID: composePrimary, Scope: composeScope(composePrimary, domain.ScopeAdvisoryEntries, domain.CoverageComplete)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		ProfileAssessments: []domain.ProfileAssessment{composeProfile(domain.ProfileZeroTrust, true, build,
			composeExploitable(domain.ScopeLibraryAPI))},
	}
}

func cveCase() *domain.AnalysisCase {
	build := composeBuild()
	return &domain.AnalysisCase{
		ID:            composePrimaryCase,
		RequestedID:   composeCVE,
		Vulnerability: domain.Vulnerability{ID: composePrimary, Scope: composeScope(composeCVE, domain.ScopeCVE, domain.CoverageKnownOnly)},
		Product:       composeProduct(build),
		ProfileAssessments: []domain.ProfileAssessment{
			composeProfile(domain.ProfileZeroTrust, true, build, composeFailed(composePrimaryCase, domain.GapUnsupportedNegativeScope)),
			composeProfile(domain.ProfileClusterPerimeter, false, build, composeFailed(composePrimaryCase, domain.GapUnsupportedNegativeScope)),
		},
	}
}

func addRelated(c *domain.AnalysisCase, id domain.CaseID, pin domain.RecordPin, result domain.AssessmentResult) *domain.AnalysisCase {
	build := composeBuild()
	child := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   pin.RecordID,
		Vulnerability: domain.Vulnerability{ID: pin.RecordID, Scope: composeScope(pin.RecordID, domain.ScopeAdvisoryEntries, domain.CoverageComplete)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		ProfileAssessments: []domain.ProfileAssessment{
			composeProfile(domain.ProfileZeroTrust, true, build, result),
			composeProfile(domain.ProfileClusterPerimeter, false, build, result),
		},
	}
	c.RelatedRecords = append(c.RelatedRecords, domain.RelatedRecordAssessment{ID: id, Record: pin, Analysis: child})
	c.RelatedDiscovery = &domain.RelatedDiscovery{
		RequestedID: c.RequestedID,
		Enumeration: domain.DiscoveryFinished,
		Corpus:      &domain.CorpusReference{Reference: "osv-dump-2026-10-20", Digest: composeDigest("c"), CapturedAt: "2026-10-20"},
		Candidates: append(candidateList(c.RelatedDiscovery), domain.DiscoveryCandidate{
			Record:      pin,
			Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: composeCVE, FromID: pin.RecordID}},
			Disposition: domain.DispositionEvaluated,
		}),
	}
	return c
}

func candidateList(discovery *domain.RelatedDiscovery) []domain.DiscoveryCandidate {
	if discovery == nil {
		return nil
	}
	return discovery.Candidates
}

func addDeclaredCorpus(c *domain.AnalysisCase) {
	reference := domain.CorpusReference{
		Reference:  "osv-dump-2026-10-20",
		Digest:     composeDigest("c"),
		CapturedAt: "2026-10-20",
	}
	manifest := domain.CorpusManifest{
		Reference:      reference.Reference,
		CapturedAt:     reference.CapturedAt,
		ObservedDigest: reference.Digest,
		Enumeration:    domain.DiscoveryFinished,
		Documents:      []domain.RecordPin{composePin(composeGRPC)},
	}
	c.CorpusDeclaration = &domain.CorpusDeclaration{
		Reference:      reference.Reference,
		ExpectedDigest: reference.Digest,
		CapturedAt:     reference.CapturedAt,
	}
	c.CorpusManifest = &manifest
	c.RelatedDiscovery.Enumeration = domain.DiscoveryFinished
	c.RelatedDiscovery.Corpus = &reference
	c.RelatedDiscovery.RequestedID = c.RequestedID
	for i := range c.RelatedRecords {
		if c.RelatedRecords[i].Record.RecordID == composeGRPC {
			c.RelatedRecords[i].Record = composePin(composeGRPC)
		}
	}
	for i := range c.RelatedDiscovery.Candidates {
		if c.RelatedDiscovery.Candidates[i].Record.RecordID == composeGRPC {
			c.RelatedDiscovery.Candidates[i].Record = composePin(composeGRPC)
		}
	}
}

func TestRequestedFindingComposition(t *testing.T) {
	t.Run("an exact request projects only its primary record", func(t *testing.T) {
		c := exactPrimaryCase()
		addRelated(c, composeGRPCCase, composePin(composeGRPC), composeExploitable(domain.ScopeTransportPeer))
		finding, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if finding.RequestedKind != domain.ScopeAdvisoryEntries || finding.Coverage != domain.CoverageComplete {
			t.Fatalf("request envelope = %+v", finding)
		}
		if finding.Verdict != domain.VerdictExploitable {
			t.Fatalf("verdict = %q", finding.Verdict)
		}
		if len(finding.ProofOrigins) != 1 || finding.ProofOrigins[0].AssessmentID != composePrimaryCase {
			t.Fatalf("exact request must not absorb the related positive: %+v", finding.ProofOrigins)
		}
		if finding.ExploitabilityScope != domain.ScopeLibraryAPI {
			t.Fatalf("scope = %q", finding.ExploitabilityScope)
		}
	})

	t.Run("a CVE positive comes from one independently attributed witness", func(t *testing.T) {
		c := cveCase()
		grpcPin := composePin(composeGRPC)
		addRelated(c, composeGRPCCase, grpcPin, composeExploitable(domain.ScopeTransportPeer))
		otherPin := composePin(composeOther)
		addRelated(c, composeOtherCase, otherPin, composeFailed(composeOtherCase, domain.GapReachabilityProofIncomplete))
		c.Attributions = []domain.CVEAttribution{composeAttribution("ATTR-GRPC", grpcPin)}
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeDecided || found.Verdict != domain.VerdictExploitable {
			t.Fatalf("outcome/verdict = %s/%q gaps=%+v limitations=%v", found.Outcome, found.Verdict, found.Gaps, found.Limitations)
		}
		if found.ExploitabilityScope != domain.ScopeTransportPeer {
			t.Fatalf("scope = %q", found.ExploitabilityScope)
		}
		if len(found.ProofOrigins) != 1 {
			t.Fatalf("origins = %+v", found.ProofOrigins)
		}
		origin := found.ProofOrigins[0]
		if origin.Record.RecordID != composeGRPC || origin.AttributionID != "ATTR-GRPC" {
			t.Fatalf("origin = %+v", origin)
		}
		if origin.AssessmentID != composeGRPCCase {
			t.Fatalf("origin assessment = %q", origin.AssessmentID)
		}
		// The unrelated failed candidate must not veto the positive, but its
		// diagnostic must survive.
		if !composeHasGapCode(found.Gaps, domain.GapReachabilityProofIncomplete) {
			t.Fatalf("candidate diagnostics were dropped: %+v", found.Gaps)
		}
		if !hasLimitation(found.Limitations, domain.TransportPeerScopeLimitation) {
			t.Fatal("transport-peer scope limitation is missing")
		}
	})

	t.Run("a positive without admitted attribution fails the CVE", func(t *testing.T) {
		c := cveCase()
		addRelated(c, composeGRPCCase, composePin(composeGRPC), composeExploitable(domain.ScopeTransportPeer))
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" {
			t.Fatalf("outcome/verdict = %s/%q", found.Outcome, found.Verdict)
		}
		if !composeHasGapCode(found.Gaps, domain.GapCVEAttributionUnresolved) {
			t.Fatalf("gaps = %+v", found.Gaps)
		}
	})

	t.Run("an all-negative CVE without a declared corpus stays unsupported", func(t *testing.T) {
		c := cveCase()
		addRelated(c, composeGRPCCase, composePin(composeGRPC), composeNotAffected())
		c.RelatedDiscovery = nil
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" {
			t.Fatalf("outcome/verdict = %s/%q", found.Outcome, found.Verdict)
		}
		if !composeHasGapCode(found.Gaps, domain.GapUnsupportedNegativeScope) {
			t.Fatalf("gaps = %+v", found.Gaps)
		}
		if found.CorpusNegativeBasis != nil {
			t.Fatal("an undeclared corpus must not produce a negative basis")
		}
	})

	t.Run("a component negative never closes a CVE without a declared corpus", func(t *testing.T) {
		c := cveCase()
		build := composeBuild()
		c.ProfileAssessments = []domain.ProfileAssessment{
			composeProfile(domain.ProfileZeroTrust, true, build, composeNotAffected()),
			composeProfile(domain.ProfileClusterPerimeter, false, build, composeNotAffected()),
		}
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" {
			t.Fatalf("a component negative closed the CVE: %s/%q", found.Outcome, found.Verdict)
		}
		if !composeHasGapCode(found.Gaps, domain.GapUnsupportedNegativeScope) {
			t.Fatalf("gaps = %+v", found.Gaps)
		}
	})

	t.Run("a declared complete corpus with independent negatives closes the CVE", func(t *testing.T) {
		c := cveCase()
		addRelated(c, composeGRPCCase, composePin(composeGRPC), composeNotAffected())
		addDeclaredCorpus(c)
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeDecided || found.Verdict != domain.VerdictNotAffected {
			t.Fatalf("outcome/verdict = %s/%q", found.Outcome, found.Verdict)
		}
		if found.CorpusNegativeBasis == nil {
			t.Fatal("a CVE-wide negative requires the declared corpus basis")
		}
		if !strings.Contains(found.CorpusNegativeBasis.BoundaryStatement, "implementations outside this corpus were not examined") {
			t.Fatalf("boundary = %q", found.CorpusNegativeBasis.BoundaryStatement)
		}
	})

	t.Run("a zero-trust positive does not establish the cluster profile", func(t *testing.T) {
		c := cveCase()
		grpcPin := composePin(composeGRPC)
		build := composeBuild()
		child := &domain.AnalysisCase{
			ID:            composeGRPCCase,
			RequestedID:   composeGRPC,
			Vulnerability: domain.Vulnerability{ID: composeGRPC},
			RecordPin:     &grpcPin,
			Product:       composeProduct(build),
			ProfileAssessments: []domain.ProfileAssessment{
				composeProfile(domain.ProfileZeroTrust, false, build, composeExploitable(domain.ScopeTransportPeer)),
				composeProfile(domain.ProfileClusterPerimeter, true, build, composeFailed(composeGRPCCase, domain.GapReachabilityProofIncomplete)),
			},
		}
		primaryPin := composePin(composePrimary)
		c.Product.TrustedPeer = true
		c.RecordPin = &primaryPin
		c.ProfileAssessments = []domain.ProfileAssessment{
			composeProfile(domain.ProfileZeroTrust, false, build, composeExploitable(domain.ScopeTransportPeer)),
			composeProfile(domain.ProfileClusterPerimeter, true, build, composeFailed(composePrimaryCase, domain.GapUnsupportedNegativeScope)),
		}
		c.RelatedRecords = []domain.RelatedRecordAssessment{{ID: composeGRPCCase, Record: grpcPin, Analysis: child}}
		c.Attributions = []domain.CVEAttribution{
			composeAttribution("ATTR-GRPC", grpcPin),
			composeAttribution("ATTR-PRIMARY", primaryPin),
		}
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Profile != domain.ProfileClusterPerimeter || found.IsTargetActual != true {
			t.Fatalf("embedded profile = %q actual=%v", found.Profile, found.IsTargetActual)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" {
			t.Fatalf("the cluster-perimeter answer must not borrow the zero-trust positive: %s/%q", found.Outcome, found.Verdict)
		}
		zeroTrust := profileByKind(found.Profiles, domain.ProfileZeroTrust)
		if zeroTrust == nil || zeroTrust.Verdict != domain.VerdictExploitable {
			t.Fatalf("hypothetical zero-trust profile = %+v", zeroTrust)
		}
	})

	t.Run("a primary result from another build is not published", func(t *testing.T) {
		c := exactPrimaryCase()
		build := composeBuild()
		build.GOARCH = "arm64"
		c.ProfileAssessments[0].Build = build
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" {
			t.Fatalf("a cross-build primary result was published: %s/%q", found.Outcome, found.Verdict)
		}
		if !composeHasGapCode(found.Gaps, domain.GapProofArtifactMissing) {
			t.Fatalf("gaps = %+v", found.Gaps)
		}
	})

	t.Run("a witness from a different build is never combined", func(t *testing.T) {
		c := cveCase()
		grpcPin := composePin(composeGRPC)
		addRelated(c, composeGRPCCase, grpcPin, composeExploitable(domain.ScopeTransportPeer))
		c.Attributions = []domain.CVEAttribution{composeAttribution("ATTR-GRPC", grpcPin)}
		build := composeBuild()
		build.GOARCH = "arm64"
		for i := range c.RelatedRecords {
			for j := range c.RelatedRecords[i].Analysis.ProfileAssessments {
				c.RelatedRecords[i].Analysis.ProfileAssessments[j].Build = build
			}
		}
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" || len(found.ProofOrigins) != 0 {
			t.Fatalf("a cross-build positive was composed: %+v", found.FindingProfile)
		}
	})

	t.Run("an exact request does not substitute a related positive for a failed primary", func(t *testing.T) {
		c := exactPrimaryCase()
		c.ProfileAssessments = []domain.ProfileAssessment{composeProfile(domain.ProfileZeroTrust, true,
			composeBuild(), composeFailed(composePrimaryCase, domain.GapReachabilityProofIncomplete))}
		addRelated(c, composeGRPCCase, composePin(composeGRPC), composeExploitable(domain.ScopeTransportPeer))
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" || len(found.ProofOrigins) != 0 {
			t.Fatalf("the failed exact primary was replaced: %+v", found.FindingProfile)
		}
	})

	t.Run("an unresolved primary positive blocks the declared corpus negative", func(t *testing.T) {
		c := cveCase()
		primaryPin := composePin(composePrimary)
		c.RecordPin = &primaryPin
		build := composeBuild()
		c.ProfileAssessments = []domain.ProfileAssessment{
			composeProfile(domain.ProfileZeroTrust, true, build, composeExploitable(domain.ScopeLibraryAPI)),
			composeProfile(domain.ProfileClusterPerimeter, false, build, composeNotAffected()),
		}
		c.RelatedDiscovery = &domain.RelatedDiscovery{RequestedID: c.RequestedID}
		addDeclaredCorpus(c)
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeFailed || found.Verdict != "" {
			t.Fatalf("a declared corpus closed over an unresolved positive: %s/%q", found.Outcome, found.Verdict)
		}
		if !composeHasGapCode(found.Gaps, domain.GapCVEAttributionUnresolved) {
			t.Fatalf("gaps = %+v", found.Gaps)
		}
	})

	t.Run("a failed primary does not veto the bounded no-match result", func(t *testing.T) {
		c := cveCase()
		c.RelatedDiscovery = &domain.RelatedDiscovery{RequestedID: c.RequestedID}
		addDeclaredCorpus(c)
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeDecided || found.Verdict != domain.VerdictNotAffected {
			t.Fatalf("bounded corpus no-match = %s/%q gaps=%+v", found.Outcome, found.Verdict, found.Gaps)
		}
		if found.CorpusNegativeBasis == nil {
			t.Fatal("bounded no-match must carry the declared corpus basis")
		}
	})

	t.Run("a genuine external candidate survives only with a declared corpus", func(t *testing.T) {
		c := cveCase()
		build := composeBuild()
		c.ProfileAssessments = []domain.ProfileAssessment{
			composeProfile(domain.ProfileZeroTrust, true, build, composeNotAffected()),
			composeProfile(domain.ProfileClusterPerimeter, false, build, composeNotAffected()),
		}
		addRelated(c, composeGRPCCase, composePin(composeGRPC), composeExternal(composeGRPCCase))
		addDeclaredCorpus(c)
		found, err := finding.Compose(c)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if found.Outcome != domain.OutcomeExternal || found.Verdict != domain.VerdictInconclusive {
			t.Fatalf("outcome/verdict = %s/%q", found.Outcome, found.Verdict)
		}
		if len(found.ExternalDependencies) != 1 {
			t.Fatalf("dependencies = %+v", found.ExternalDependencies)
		}
	})
}

func profileByKind(profiles []domain.FindingProfile, kind domain.ThreatProfile) *domain.FindingProfile {
	for i := range profiles {
		if profiles[i].Profile == kind {
			return &profiles[i]
		}
	}
	return nil
}

func composeHasGapCode(gaps []domain.AnalysisGap, code domain.GapCode) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func hasLimitation(limitations []string, want string) bool {
	for _, limitation := range limitations {
		if limitation == want {
			return true
		}
	}
	return false
}

package states_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/advfeed"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/finding"
	"github.com/davniy/izyan/internal/states"
	"github.com/davniy/izyan/internal/vulnerability"
)

const (
	isolatedCVE         = "CVE-2023-44487"
	isolatedPrimary     = "GHSA-qppj-fm5r-hxr3"
	isolatedGRPC        = "GO-2023-2153"
	isolatedDecoy       = "GO-DECOY-0001"
	isolatedBroken      = "GO-BROKEN-0001"
	isolatedGRPCCase    = domain.CaseID("request-case-GO-2023-2153")
	isolatedPrimaryPath = "../../eval/agent7/advisories/k8s-44487.json"
	isolatedGRPCPath    = "../../eval/advisories/reviewed/GO-2023-2153.json"
)

func isolatedDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isolatedCorpus(t *testing.T, withPrimary, withBroken bool) *advfeed.Corpus {
	t.Helper()
	dir := t.TempDir()
	grpc, err := os.ReadFile(isolatedGRPCPath)
	if err != nil {
		t.Fatalf("read gRPC advisory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, isolatedGRPC+".json"), grpc, 0o644); err != nil {
		t.Fatal(err)
	}
	if withPrimary {
		primary, err := os.ReadFile(isolatedPrimaryPath)
		if err != nil {
			t.Fatalf("read primary advisory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, isolatedPrimary+".json"), primary, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A related two-hop decoy: GO-DECOY names GO-2023-2153, never the CVE.
	decoy := `{"id":"GO-DECOY-0001","summary":"decoy","related":["GO-2023-2153"],"affected":[{"package":{"ecosystem":"Go","name":"example.com/decoy"}}]}`
	if err := os.WriteFile(filepath.Join(dir, isolatedDecoy+".json"), []byte(decoy), 0o644); err != nil {
		t.Fatal(err)
	}
	if withBroken {
		broken := `{"id":"GO-BROKEN-0001","related":["CVE-2023-44487"],"affected":"broken"}`
		if err := os.WriteFile(filepath.Join(dir, isolatedBroken+".json"), []byte(broken), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	now := func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }
	first, err := advfeed.AcquireCorpus(context.Background(), advfeed.CorpusOptions{
		Feed: advfeed.Options{LocalPath: dir, Now: now},
	})
	if err != nil {
		t.Fatalf("acquire corpus: %v", err)
	}
	manifest := first.Manifest()
	corpus, err := advfeed.AcquireCorpus(context.Background(), advfeed.CorpusOptions{
		Feed: advfeed.Options{LocalPath: dir, Now: now},
		Declaration: &domain.CorpusDeclaration{
			Reference:      "isolated-corpus",
			ExpectedDigest: manifest.ObservedDigest,
			CapturedAt:     manifest.CapturedAt,
		},
	})
	if err != nil {
		t.Fatalf("acquire declared corpus: %v", err)
	}
	return corpus
}

func isolatedPrimaryRecord(t *testing.T) *vulnerability.LoadedRecord {
	t.Helper()
	record, err := vulnerability.FileSource{Path: isolatedPrimaryPath}.LoadExact(context.Background(), isolatedPrimary)
	if err != nil {
		t.Fatalf("load primary exact record: %v", err)
	}
	return &record
}

func isolatedRoot(requestedID string, primary *vulnerability.LoadedRecord) *domain.AnalysisCase {
	root := &domain.AnalysisCase{
		ID:          "request-case",
		RequestedID: requestedID,
		Product:     domain.ProductSnapshot{},
		Workflow: domain.WorkflowStatus{
			State:     domain.StateDiscoverRecords,
			StartedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			Limits: domain.AnalysisLimits{
				MaxIterations:       64,
				MaxToolCalls:        128,
				MaxLLMCalls:         32,
				MaxSourceReads:      256,
				MaxReviewIterations: 2,
			},
		},
	}
	if primary != nil {
		root.Vulnerability = *primary.Vuln
		pin := primary.Pin
		root.RecordPin = &pin
	}
	root.EvidenceGraph.Version = "1"
	return root
}

func isolatedAttribution(pin domain.RecordPin) domain.CVEAttribution {
	return domain.CVEAttribution{
		ID:                "ATTR-GRPC",
		CVEID:             isolatedCVE,
		Candidate:         pin,
		EntryRefs:         []int{0},
		MechanismID:       domain.MechanismHTTP2RapidReset,
		Basis:             domain.AttributionPublisher,
		SourceURI:         "https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g",
		CapturedDigest:    isolatedDigest("publisher capture"),
		SourceField:       "cve_ids[0]",
		SourceQuote:       isolatedCVE,
		PublisherAdvisory: "GHSA-m425-mq94-257g",
		Module:            "google.golang.org/grpc",
		Repository:        "github.com/grpc/grpc-go",
		FixRefs:           []string{"https://github.com/grpc/grpc-go/pull/6703"},
		Admission:         domain.AttributionAdmitted,
	}
}

func isolatedAttributor(_ context.Context, _ string, record vulnerability.LoadedRecord) ([]domain.CVEAttribution, error) {
	if record.Pin.RecordID != isolatedGRPC {
		return nil, nil
	}
	return []domain.CVEAttribution{isolatedAttribution(record.Pin)}, nil
}

func isolatedExploitable() domain.AssessmentResult {
	return domain.AssessmentResult{
		Outcome: domain.OutcomeDecided,
		Verdict: &domain.VerdictResult{
			Verdict:             domain.VerdictExploitable,
			Reason:              "peer frames reach the vulnerable transport before the fixed handler quota",
			ConditionIDs:        []domain.ConditionID{"C-TRIGGER"},
			EvidenceIDs:         []domain.EvidenceID{"EV-TRIGGER"},
			ExploitabilityScope: domain.ScopeTransportPeer,
		},
	}
}

func isolatedNotAffected() domain.AssessmentResult {
	return domain.AssessmentResult{
		Outcome: domain.OutcomeDecided,
		Verdict: &domain.VerdictResult{Verdict: domain.VerdictNotAffected, Reason: "not affected"},
	}
}

func isolatedFailed(id domain.CaseID) domain.AssessmentResult {
	return domain.AssessmentResult{
		Outcome: domain.OutcomeFailed,
		Gaps: []domain.AnalysisGap{{
			Owner:        domain.GapOwnerScope,
			Code:         domain.GapUnsupportedNegativeScope,
			Obligation:   domain.ObligationNegativeScope,
			AssessmentID: id,
			Message:      "component negative cannot close the requested CVE",
		}},
	}
}

// isolatedRunner is a stub record assessment. It proves the orchestration
// contract (fresh child case, exact bytes, no recursion, finalized requested
// finding) without running the complete source-analysis pipeline.
func isolatedRunner(t *testing.T, seen func(*domain.AnalysisCase)) states.RecordRunner {
	return func(_ context.Context, child *domain.AnalysisCase) error {
		if seen != nil {
			seen(child)
		}
		build := domain.EffectiveBuildContext(child.Product)
		child.ProfileAssessments = []domain.ProfileAssessment{
			{
				Profile:        domain.ProfileZeroTrust,
				IsTargetActual: true,
				Build:          build,
				Result:         isolatedExploitable(),
			},
			{
				Profile:        domain.ProfileClusterPerimeter,
				IsTargetActual: false,
				Build:          build,
				Result:         isolatedNotAffected(),
			},
		}
		child.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:      "EV-TRIGGER",
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "isolated-runner",
			Content: "rooted transport trigger witness",
			TransportTrigger: &domain.TransportTriggerWitness{
				Mechanism: domain.MechanismHTTP2RapidReset,
			},
		})
		return finding.Finalize(child)
	}
}

// assertPrimaryCensus pins the recorded 22/1/21 primary projection: discovery
// and composition must never append gRPC as a 23rd entry or synthesize an
// aggregate inventory.
func assertPrimaryCensus(t *testing.T, primary *vulnerability.LoadedRecord) {
	t.Helper()
	scope := primary.Vuln.Scope
	if scope == nil || scope.RecordInventory == nil {
		t.Fatalf("primary scope/inventory = %+v", scope)
	}
	if scope.Coverage != domain.CoverageKnownOnly || scope.RecordExtent != domain.RecordExtentGoProjection {
		t.Fatalf("primary scope = %q/%q", scope.Coverage, scope.RecordExtent)
	}
	inventory := scope.RecordInventory
	if inventory.AffectedEntryCount != 22 || len(inventory.RepresentedRefs) != 1 || len(inventory.OmittedRefs) != 21 {
		t.Fatalf("primary census = %d/%d/%d, want 22/1/21",
			inventory.AffectedEntryCount, len(inventory.RepresentedRefs), len(inventory.OmittedRefs))
	}
	if len(primary.Vuln.AffectedModules) != 1 || primary.Vuln.AffectedModules[0].Module != "golang.org/x/net" {
		t.Fatalf("primary Go projection = %+v; gRPC must not be appended", primary.Vuln.AffectedModules)
	}
}

func isolatedDiscover(t *testing.T, corpus *advfeed.Corpus, root *domain.AnalysisCase, primary *vulnerability.LoadedRecord) {
	t.Helper()
	intake := &states.RecordIntake{}
	if primary != nil {
		intake.Set(*primary)
	}
	transition, err := (states.DiscoverRecords{Source: corpus, Intake: intake, Attributor: isolatedAttributor}).Run(context.Background(), root)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	want := domain.StateAssessRelatedRecords
	if primary != nil {
		want = domain.StateCheckAffected
	}
	if transition.Next != want {
		t.Fatalf("discover transition = %s, want %s", transition.Next, want)
	}
	if root.RelatedDiscovery == nil {
		t.Fatal("discovery record is missing")
	}
}

func isolatedAssess(t *testing.T, corpus *advfeed.Corpus, root *domain.AnalysisCase, runner states.RecordRunner) {
	t.Helper()
	transition, err := (states.AssessRelatedRecords{
		Source:     corpus,
		Runner:     runner,
		Attributor: isolatedAttributor,
	}).Run(context.Background(), root)
	if err != nil {
		t.Fatalf("assess related: %v", err)
	}
	if transition.Next != domain.StateComposeRequestedFinding {
		t.Fatalf("assess transition = %s", transition.Next)
	}
}

func isolatedSetPrimaryProfiles(root *domain.AnalysisCase, result domain.AssessmentResult) {
	build := domain.EffectiveBuildContext(root.Product)
	root.ProfileAssessments = []domain.ProfileAssessment{
		{Profile: domain.ProfileZeroTrust, IsTargetActual: true, Build: build, Result: result},
		{Profile: domain.ProfileClusterPerimeter, IsTargetActual: false, Build: build, Result: result},
	}
}

func TestIsolatedRecordAssessment(t *testing.T) {
	t.Run("each candidate is assessed from its own exact bytes", func(t *testing.T) {
		corpus := isolatedCorpus(t, true, false)
		primary := isolatedPrimaryRecord(t)
		assertPrimaryCensus(t, primary)
		root := isolatedRoot(isolatedCVE, primary)
		isolatedDiscover(t, corpus, root, primary)

		candidates := root.RelatedDiscovery.Candidates
		if len(candidates) != 1 {
			t.Fatalf("candidates = %+v", candidates)
		}
		if candidates[0].Record.RecordID != isolatedGRPC {
			t.Fatalf("candidate = %q; the inverse related(CVE) lookup and no-transitive rule failed", candidates[0].Record.RecordID)
		}
		if candidates[0].Disposition != domain.DispositionNotEvaluated {
			t.Fatalf("discovery must not infer assessment: %q", candidates[0].Disposition)
		}

		var child *domain.AnalysisCase
		isolatedAssess(t, corpus, root, isolatedRunner(t, func(c *domain.AnalysisCase) { child = c }))

		if len(root.RelatedRecords) != 1 {
			t.Fatalf("related assessments = %+v", root.RelatedRecords)
		}
		if child == nil || child.ID != isolatedGRPCCase {
			t.Fatalf("child = %+v", child)
		}
		pin := child.RecordPin
		if pin == nil || pin.RecordID != isolatedGRPC {
			t.Fatalf("child pin = %+v", pin)
		}
		if body, err := os.ReadFile(isolatedGRPCPath); err != nil {
			t.Fatal(err)
		} else if pin.DocumentDigest != isolatedDigest(string(body)) {
			t.Fatalf("child pin digest = %s, want the exact document bytes", pin.DocumentDigest)
		}
		if child.Vulnerability.ID != isolatedGRPC {
			t.Fatalf("child record = %q", child.Vulnerability.ID)
		}
		if child.RelatedDiscovery != nil || len(child.RelatedRecords) != 0 {
			t.Fatal("a child candidate must not recurse into discovery")
		}
		if !reflect.DeepEqual(child.Product, root.Product) {
			t.Fatalf("child product differs from the shared snapshot")
		}
		if child.Workflow.Limits != root.Workflow.Limits {
			t.Fatalf("child limits = %+v, want the request's remaining budget", child.Workflow.Limits)
		}
		if root.RelatedDiscovery.Candidates[0].Disposition != domain.DispositionEvaluated {
			t.Fatalf("candidate disposition = %q", root.RelatedDiscovery.Candidates[0].Disposition)
		}

		isolatedSetPrimaryProfiles(root, isolatedFailed(root.ID))
		if _, err := (states.ComposeRequestedFinding{}).Run(context.Background(), root); err != nil {
			t.Fatalf("compose: %v", err)
		}
		finding := root.RequestedFinding
		if finding == nil {
			t.Fatal("composed finding is missing")
		}
		if finding.Outcome != domain.OutcomeDecided || finding.Verdict != domain.VerdictExploitable {
			t.Fatalf("outcome/verdict = %s/%q gaps=%+v", finding.Outcome, finding.Verdict, finding.Gaps)
		}
		if finding.ExploitabilityScope != domain.ScopeTransportPeer {
			t.Fatalf("scope = %q", finding.ExploitabilityScope)
		}
		if len(finding.ProofOrigins) != 1 || finding.ProofOrigins[0].Record.RecordID != isolatedGRPC {
			t.Fatalf("origins = %+v", finding.ProofOrigins)
		}
		if finding.RequestedKind != domain.ScopeCVE || finding.Coverage != domain.CoverageKnownOnly {
			t.Fatalf("CVE request envelope = %q/%q", finding.RequestedKind, finding.Coverage)
		}
		assertPrimaryCensus(t, primary)
	})

	t.Run("primary resolution failure still assesses available candidates", func(t *testing.T) {
		corpus := isolatedCorpus(t, false, false)
		root := isolatedRoot(isolatedCVE, nil)
		isolatedDiscover(t, corpus, root, nil)
		if len(root.RelatedDiscovery.Candidates) != 1 {
			t.Fatalf("candidates = %+v", root.RelatedDiscovery.Candidates)
		}
		isolatedAssess(t, corpus, root, isolatedRunner(t, nil))

		if root.RequestedFinding != nil {
			t.Fatal("composition must not run before its state")
		}
		if _, err := (states.ComposeRequestedFinding{}).Run(context.Background(), root); err != nil {
			t.Fatalf("compose: %v", err)
		}
		if got := root.RequestedFinding; got == nil || got.Outcome != domain.OutcomeDecided || got.Verdict != domain.VerdictExploitable {
			t.Fatalf("a primary resolution failure suppressed the candidate positive: %+v", got)
		}
	})

	t.Run("a primary component negative does not bypass candidates", func(t *testing.T) {
		corpus := isolatedCorpus(t, false, false)
		primary := isolatedPrimaryRecord(t)
		root := isolatedRoot(isolatedCVE, primary)
		isolatedSetPrimaryProfiles(root, isolatedNotAffected())
		isolatedDiscover(t, corpus, root, primary)
		isolatedAssess(t, corpus, root, isolatedRunner(t, nil))
		if _, err := (states.ComposeRequestedFinding{}).Run(context.Background(), root); err != nil {
			t.Fatalf("compose: %v", err)
		}
		if got := root.RequestedFinding; got == nil || got.Verdict != domain.VerdictExploitable {
			t.Fatalf("a fixed primary component closed the CVE before its candidate: %+v", got)
		}
	})

	t.Run("the request budget is not reset per candidate", func(t *testing.T) {
		corpus := isolatedCorpus(t, false, false)
		root := isolatedRoot(isolatedCVE, nil)
		root.Workflow.Limits.MaxToolCalls = 1
		root.Workflow.Usage.ToolCalls = 1
		isolatedDiscover(t, corpus, root, nil)
		called := false
		isolatedAssess(t, corpus, root, func(context.Context, *domain.AnalysisCase) error {
			called = true
			return nil
		})
		if called {
			t.Fatal("a fresh per-candidate budget was granted after the request budget was exhausted")
		}
		if len(root.RelatedRecords) != 0 {
			t.Fatalf("exhausted candidate was assessed: %+v", root.RelatedRecords)
		}
		if got := root.RelatedDiscovery.Candidates[0].Disposition; got != domain.DispositionTimedOut {
			t.Fatalf("disposition = %q", got)
		}
	})

	t.Run("a load-failed candidate is retained as unassessed", func(t *testing.T) {
		corpus := isolatedCorpus(t, false, true)
		root := isolatedRoot(isolatedCVE, nil)
		isolatedDiscover(t, corpus, root, nil)
		isolatedAssess(t, corpus, root, isolatedRunner(t, nil))

		var broken *domain.DiscoveryCandidate
		for i := range root.RelatedDiscovery.Candidates {
			if root.RelatedDiscovery.Candidates[i].Record.RecordID == isolatedBroken {
				broken = &root.RelatedDiscovery.Candidates[i]
			}
		}
		if broken == nil || broken.Disposition != domain.DispositionLoadFailed {
			t.Fatalf("broken candidate = %+v", broken)
		}
		for _, related := range root.RelatedRecords {
			if related.Record.RecordID == isolatedBroken {
				t.Fatal("a load-failed candidate was silently assessed")
			}
		}
	})
}

package research

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/finding"
)

const (
	requestTestID      = "GO-TEST-0001"
	requestTestOtherID = "GO-OTHER-9999"
)

// requestLane is fakeLane with the exact record pin and requested identity a
// record assessment needs. The affected chain is supplied by the caller so a
// decided and an undecided record can both be exercised.
func requestLane(t *testing.T, modulePresent domain.ClaimResult) *LaneResult {
	t.Helper()
	lane := fakeLane(t)
	lane.Snapshot.ContentHash = lane.ContentHash
	lane.RecordPin = &domain.RecordPin{
		RecordID:       requestTestID,
		DocumentDigest: "sha256:" + strings.Repeat("ab", 32),
		SourceLocator:  "/adv/GO-TEST-0001.json",
	}
	lane.RequestedID = requestTestID
	lane.Affected.ModulePresent = modulePresent
	lane.Affected.Scope = requestAffectedScope()
	return lane
}

// requestAffectedScope is a fully represented exact-record census: a negative
// over this record's own entries is admissible, so a decided record assessment
// is a legitimate result rather than a scope refusal.
func requestAffectedScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID:  requestTestID,
		ResolvedID:   requestTestID,
		Kind:         domain.ScopeAdvisoryEntries,
		Coverage:     domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         requestTestID,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"}},
			RepresentedRefs:    []int{0},
		},
	}
}

// publishTestComposition builds the lane's record case, publishes the request
// composition through the adapter and returns it.
func publishTestComposition(t *testing.T, lane *LaneResult) (*domain.AnalysisCase, *domain.RequestedFinding) {
	t.Helper()
	primary, err := RecordCase(lane)
	if err != nil {
		t.Fatalf("record case: %v", err)
	}
	if err := lane.PublishRequest(primary); err != nil {
		t.Fatalf("publish request: %v", err)
	}
	return primary, lane.RequestComposition
}

// validRequestComposition is a real exact-record composition for the synthetic
// advisory the report fixtures use, so a /4 document is validated against a
// re-admitted answer rather than a hand assertion.
func validRequestComposition(t *testing.T) *domain.RequestedFinding {
	t.Helper()
	_, composition := publishTestComposition(t, requestLane(t, domain.ClaimFalse))
	return composition
}

// researchReportV4 assembles a /4 report from the lane whose composition was
// re-admitted, with the /3 decision artifact beside it.
func researchReportV4(t *testing.T, in AssembleInput) *Report {
	t.Helper()
	in.DecisionArtifact = validArtifact(t)
	in.RunID = "research-v4-test"
	in.StartedAt = time.Now()
	in.FinishedAt = time.Now()
	if in.RequestComposition == nil {
		in.RequestComposition = in.Lane.RequestComposition
	}
	return Assemble(in)
}

func TestResearchRequestComposition(t *testing.T) {
	t.Run("the lane publishes the re-admitted composition", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		primary, composition := publishTestComposition(t, lane)
		if composition == nil {
			t.Fatal("lane published no request composition")
		}
		if composition.Status != domain.FindingFinal {
			t.Fatalf("composition status %q is not FINAL", composition.Status)
		}
		if composition.RequestedID != requestTestID {
			t.Fatalf("composition names request %q, want %q", composition.RequestedID, requestTestID)
		}
		if composition.RequestedKind != domain.ScopeAdvisoryEntries {
			t.Fatalf("composition kind %q, want %q", composition.RequestedKind, domain.ScopeAdvisoryEntries)
		}
		if composition.Outcome != domain.OutcomeDecided || composition.Verdict != domain.VerdictNotAffected {
			t.Fatalf("composition outcome %s/%q, want DECIDED/NOT_AFFECTED", composition.Outcome, composition.Verdict)
		}
		if composition.PrimaryAssessmentID != primary.ID {
			t.Fatalf("composition primary %q, want %q", composition.PrimaryAssessmentID, primary.ID)
		}
		if !composition.IsTargetActual {
			t.Fatal("composition is not marked as the deployment's actual profile")
		}
		if !sameRequestComposition(lane.RequestComposition, composition) {
			t.Fatal("lane stores a different composition than the adapter returned")
		}
	})

	t.Run("a replayed composition is re-admitted unchanged", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		primary, published := publishTestComposition(t, lane)
		// Replay: the record case already carries its own FINAL envelope.
		if err := FinalizeRecordCase(primary); err != nil {
			t.Fatalf("finalize record case: %v", err)
		}
		replayed, err := ProjectRequestedFinding(lane, primary, nil)
		if err != nil {
			t.Fatalf("replay refused: %v", err)
		}
		if !sameRequestComposition(&replayed, published) {
			t.Fatal("replayed composition differs from the published one")
		}
	})

	t.Run("a replayed composition that no longer re-admits is policy drift", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		primary, _ := publishTestComposition(t, lane)
		if err := FinalizeRecordCase(primary); err != nil {
			t.Fatalf("finalize record case: %v", err)
		}
		forged := *primary.RequestedFinding
		forged.Reason = "a hand-written closure the record never supported"
		primary.RequestedFinding = &forged
		_, err := ProjectRequestedFinding(lane, primary, nil)
		if err == nil {
			t.Fatal("drifted composition was republished")
		}
		if !errors.Is(err, ErrRequestCompositionDrift) {
			t.Fatalf("drift refused with %v; want ErrRequestCompositionDrift", err)
		}
		if !errors.Is(err, finding.ErrPolicyDrift) {
			t.Fatalf("drift error does not wrap the projection's policy-drift cause: %v", err)
		}
	})

	t.Run("a request without a primary record case is refused", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		_, err := ProjectRequestedFinding(lane, nil, nil)
		if err == nil {
			t.Fatal("composition without a primary record assessment was accepted")
		}
		if !errors.Is(err, ErrRequestCompositionUnavailable) {
			t.Fatalf("refused with %v; want ErrRequestCompositionUnavailable", err)
		}
	})

	t.Run("a record-bound envelope is never repurposed as the request", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		primary, published := publishTestComposition(t, lane)
		other := *published
		other.RequestedID = requestTestOtherID
		primary.RequestedFinding = &other
		primary.Schema = domain.CaseSchemaV2
		_, err := ProjectRequestedFinding(lane, primary, nil)
		if err == nil {
			t.Fatal("a record envelope for another request was repurposed")
		}
		if !errors.Is(err, ErrRequestCompositionUnavailable) {
			t.Fatalf("refused with %v; want ErrRequestCompositionUnavailable", err)
		}
	})

	t.Run("the record-only lane owns no request composition", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		lane.RecordOnly = true
		if err := lane.PublishRequest(&domain.AnalysisCase{ID: "record"}); err == nil {
			t.Fatal("record-only lane published a request composition")
		} else if !errors.Is(err, ErrRecordOnlyLane) {
			t.Fatalf("refused with %v; want ErrRecordOnlyLane", err)
		}
	})

	t.Run("the request owner is a faithful copy of the primary record", func(t *testing.T) {
		// The owner case is built member by member to avoid copying the
		// case's mutex. The serialized form compares every exported
		// member at once, so a member that is added to domain.AnalysisCase
		// and not carried here fails this test instead of silently
		// disappearing from the composed request.
		lane := requestLane(t, domain.ClaimFalse)
		primary, _ := publishTestComposition(t, lane)
		if err := FinalizeRecordCase(primary); err != nil {
			t.Fatalf("finalize record case: %v", err)
		}
		want, err := json.Marshal(primary)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(requestOwnerCase(primary))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("request owner dropped or changed record members:\nwant %s\n got %s", want, got)
		}
	})

	t.Run("the report publishes /4 with the composition beside the record contract", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		_, published := publishTestComposition(t, lane)
		report := researchReportV4(t, AssembleInput{Lane: lane, DeterministicOnly: true})
		if report.Schema != ReportSchemaV4 {
			t.Fatalf("schema %q, want %q", report.Schema, ReportSchemaV4)
		}
		if report.RequestComposition == nil {
			t.Fatal("/4 report carries no request composition")
		}
		if !sameRequestComposition(report.RequestComposition, published) {
			t.Fatal("report composition is not the lane's re-admitted composition")
		}
		if report.DecisionArtifact == nil {
			t.Fatal("/4 report dropped the decision artifact")
		}
		// The /4 composition does not rewrite the record-bound artifact:
		// its advisory identity and binding stay the record's.
		wantBinding := validArtifact(t).AdvisoryBinding
		if !reflect.DeepEqual(report.DecisionArtifact.AdvisoryBinding, wantBinding) {
			t.Fatalf("decision artifact advisory binding was rewritten: %+v", report.DecisionArtifact.AdvisoryBinding)
		}
		if report.DecisionArtifact.FindingIdentity.AdvisoryID != requestTestID {
			t.Fatalf("decision artifact advisory identity %q, want the record %q",
				report.DecisionArtifact.FindingIdentity.AdvisoryID, requestTestID)
		}
		// Corpus/composition authority never widens the record-bound block.
		if report.ProductApplicability.ConclusionScope == ScopeCVEWide &&
			report.ProductApplicability.AdvisoryScopeStatus == ScopeComplete {
			t.Fatal("record-bound product_applicability was widened to CVE_WIDE/COMPLETE")
		}
		if err := Validate(report, ""); err != nil {
			t.Fatalf("/4 report rejected: %v", err)
		}
		md, err := RenderMarkdown(report)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(md), "## Requested finding") {
			t.Fatal("/4 markdown does not render the requested finding section")
		}
	})

	t.Run("assembly withholds a composition the lane never re-admitted", func(t *testing.T) {
		lane := requestLane(t, domain.ClaimFalse)
		report := researchReportV4(t, AssembleInput{
			Lane:               lane,
			DeterministicOnly:  true,
			RequestComposition: validRequestComposition(t),
		})
		if report.Schema != ReportSchemaV4 {
			t.Fatalf("schema %q, want %q", report.Schema, ReportSchemaV4)
		}
		if report.RequestComposition != nil {
			t.Fatal("assembly published a composition the lane never re-admitted")
		}
		err := Validate(report, "")
		if err == nil {
			t.Fatal("/4 report without its re-admitted composition was accepted")
		}
		if !strings.Contains(err.Error(), "requires a request_composition member") {
			t.Fatalf("refusal does not name the missing composition: %v", err)
		}
	})
}

func TestResearchOutcomeClassification(t *testing.T) {
	t.Run("/4 requires the final request composition", func(t *testing.T) {
		report := validReport(t)
		report.Schema = ReportSchemaV4
		report.DecisionArtifact = validArtifact(t)
		err := Validate(report, "")
		if err == nil {
			t.Fatal("research-report/4 without a composition accepted")
		}
		if !strings.Contains(err.Error(), "requires a request_composition member") {
			t.Fatalf("refusal does not name the missing composition: %v", err)
		}
	})

	t.Run("older schemas never acquire request authority", func(t *testing.T) {
		for _, schema := range []string{ReportSchemaV1, ReportSchemaV2, ReportSchemaV3} {
			report := validReport(t)
			report.Schema = schema
			switch schema {
			case ReportSchemaV1:
				report.Decision = nil
			case ReportSchemaV3:
				report.DecisionArtifact = validArtifact(t)
			}
			report.RequestComposition = validRequestComposition(t)
			err := Validate(report, "")
			if err == nil {
				t.Fatalf("%s acquired a request composition", schema)
			}
			if !strings.Contains(err.Error(), "request_composition is only valid in research-report/4") {
				t.Fatalf("%s refusal does not name the schema binding: %v", schema, err)
			}
		}
	})

	t.Run("failure and external dependency stay distinct and identifiable", func(t *testing.T) {
		external := externalRequestComposition(t)
		failed := failedRequestComposition(t)

		for name, composition := range map[string]*domain.RequestedFinding{
			"external": external,
			"failed":   failed,
		} {
			report := validReport(t)
			report.Schema = ReportSchemaV4
			report.DecisionArtifact = validArtifact(t)
			report.RequestComposition = composition
			if err := Validate(report, ""); err != nil {
				t.Fatalf("%s /4 report rejected: %v", name, err)
			}
		}
		if !strings.Contains(compositionRequestNote(external), "external dependency: ") {
			t.Fatalf("external composition does not name its missing fact: %s", compositionRequestNote(external))
		}
		if !strings.Contains(compositionRequestNote(failed), "request gap: ") {
			t.Fatalf("failed composition does not name its typed gap: %s", compositionRequestNote(failed))
		}
		if strings.Contains(compositionRequestNote(failed), "external dependency: ") {
			t.Fatalf("failed composition is reported as an environmental abstention: %s", compositionRequestNote(failed))
		}
		// Neither outcome may keep a record-level definitive verdict.
		decision := &EvidenceDecision{Verdict: domain.VerdictNoExploitPathFound, Coverage: "COMPLETE",
			ConditionID: "C-1", EvidenceRefs: []string{"obs:OBS-0001"}}
		for name, composition := range map[string]*domain.RequestedFinding{
			"external": external,
			"failed":   failed,
		} {
			demoted := compositionBoundDecision(nil, decision, composition)
			if demoted.Verdict != domain.VerdictInconclusive {
				t.Fatalf("%s composition kept the record verdict %q", name, demoted.Verdict)
			}
			if demoted.Coverage != "INSUFFICIENT_SCOPE" {
				t.Fatalf("%s demotion coverage %q, want INSUFFICIENT_SCOPE", name, demoted.Coverage)
			}
			if demoted.NegativeVerification != nil || demoted.Falsifier != "" || demoted.ConditionID != "" {
				t.Fatalf("%s demotion kept negative-proof members", name)
			}
			if decision.Verdict != domain.VerdictNoExploitPathFound {
				t.Fatalf("%s demotion mutated the caller's decision", name)
			}
		}
	})

	t.Run("deterministic and decision-ready lanes classify identically", func(t *testing.T) {
		// An affected chain with no admitted condition claims is an
		// unfinished analysis: the request must FAIL, not abstain.
		lane := requestLane(t, domain.ClaimTrue)
		_, composition := publishTestComposition(t, lane)
		if composition.Outcome != domain.OutcomeFailed {
			t.Fatalf("request outcome %s/%q, want FAILED", composition.Outcome, composition.Verdict)
		}
		det := researchReportV4(t, AssembleInput{Lane: lane, DeterministicOnly: true})
		ready := researchReportV4(t, AssembleInput{
			Lane: lane,
			Decision: &EvidenceDecision{
				Verdict: domain.VerdictExploitable, Coverage: "COMPLETE", ConditionID: "C-1",
				EvidenceRefs: []string{"obs:OBS-0001"},
			},
		})
		for name, report := range map[string]*Report{"deterministic": det, "decision-ready": ready} {
			if report.Schema != ReportSchemaV4 || report.RequestComposition == nil {
				t.Fatalf("%s lane did not publish a /4 composition", name)
			}
			if report.RequestComposition.Outcome != domain.OutcomeFailed {
				t.Fatalf("%s lane composition outcome %s", name, report.RequestComposition.Outcome)
			}
			if report.Decision == nil || report.Decision.Verdict != domain.VerdictInconclusive {
				t.Fatalf("%s lane published a definitive verdict beside a failed request", name)
			}
			if !hasCompositionUnknown(report, domain.OutcomeFailed) {
				t.Fatalf("%s lane does not record the request failure in the unknown ledger", name)
			}
			if err := Validate(report, ""); err != nil {
				t.Fatalf("%s lane /4 report rejected: %v", name, err)
			}
		}
	})
}

// externalRequestComposition derives the EXTERNAL_DEPENDENCY shape from a real
// composition: the same request, profile and build, with the answer replaced by
// one evidence-bound missing fact.
func externalRequestComposition(t *testing.T) *domain.RequestedFinding {
	t.Helper()
	composition := *validRequestComposition(t)
	dependency := domain.ExternalDependency{
		MissingFact:             "the shipped Go toolchain version is not recorded",
		AffectedObligation:      domain.ObligationVersionRange,
		BoundaryEvidenceRefs:    []domain.QualifiedRef{{AssessmentID: composition.PrimaryAssessmentID, Ref: "adv-01"}},
		WhyArtifactCannotSupply: "the artifact records no release toolchain or embedded build info",
		AlternativesChanging:    []string{"go1.25.0 is affected", "go1.25.1 is fixed"},
		ResolvingEvidence:       "the delivered binary's embedded build info",
	}
	composition.Outcome = domain.OutcomeExternal
	composition.Verdict = domain.VerdictInconclusive
	composition.Reason = "the shipped Go toolchain is supplied outside the artifact"
	composition.CorpusNegativeBasis = nil
	composition.ExternalDependencies = []domain.ExternalDependency{dependency}
	composition.Gaps = []domain.AnalysisGap{{
		Owner:        domain.GapOwnerExternal,
		Code:         domain.GapExternalDependencyUnresolved,
		Obligation:   domain.ObligationVersionRange,
		AssessmentID: composition.PrimaryAssessmentID,
		Message:      "the shipped Go toolchain version is not recorded",
		External:     &dependency,
	}}
	composition.Profiles = []domain.FindingProfile{composition.FindingProfile}
	return &composition
}

// failedRequestComposition derives the FAILED shape from a real composition.
func failedRequestComposition(t *testing.T) *domain.RequestedFinding {
	t.Helper()
	composition := *validRequestComposition(t)
	composition.Outcome = domain.OutcomeFailed
	composition.Verdict = ""
	composition.Reason = "the request carries no admissible witness"
	composition.CorpusNegativeBasis = nil
	composition.ExternalDependencies = nil
	composition.Gaps = []domain.AnalysisGap{{
		Owner:        domain.GapOwnerProof,
		Code:         domain.GapTriggerProofIncomplete,
		Obligation:   domain.ObligationCondition,
		AssessmentID: composition.PrimaryAssessmentID,
		Message:      "no mandatory condition was proved",
	}}
	composition.Profiles = []domain.FindingProfile{composition.FindingProfile}
	return &composition
}

// hasCompositionUnknown reports whether the report's ledger carries the named
// request-composition outcome as a decision-changing unknown.
func hasCompositionUnknown(report *Report, outcome domain.AssessmentOutcome) bool {
	want := strings.ToUpper(string(outcome))
	for _, unknown := range report.Unknowns {
		if !strings.Contains(unknown.Statement, "the requested analysis of") {
			continue
		}
		if strings.Contains(strings.ToUpper(unknown.Statement), want) {
			return true
		}
	}
	return false
}

func TestResearchPublicationUsesCanonicalProjection(t *testing.T) {
	lane := requestLane(t, domain.ClaimFalse)
	publishTestComposition(t, lane)
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, StartedAt: time.Now(), FinishedAt: time.Now()})
	if r.Schema != ReportSchemaV5 || r.DecisionArtifact != nil {
		t.Fatalf("current schema/artifact: %s %+v", r.Schema, r.DecisionArtifact)
	}
	view, err := finding.Project(lane.RequestedCase)
	if err != nil || !sameRequestComposition(&view.Requested, r.RequestComposition) {
		t.Fatalf("canonical projection: %v", err)
	}
	dir := t.TempDir()
	if err := lane.PersistRequestedCase(dir); err != nil {
		t.Fatal(err)
	}
	if err := validateRequestedCase(r, dir); err == nil || !strings.Contains(err.Error(), "records") {
		t.Fatalf("missing exact-record sidecar was not refused: %v", err)
	}
}

func persistedRequestLane(t *testing.T, summary string) *LaneResult {
	t.Helper()
	lane := requestLane(t, domain.ClaimFalse)
	path := filepath.Join(t.TempDir(), "advisory.json")
	raw := []byte(`{"id":"GO-TEST-0001","summary":"` + summary + `","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	advisory, err := loadFrozenAdvisory(context.Background(), LaneOptions{CVE: requestTestID, AdvisoryFile: path, RequestContract: true})
	if err != nil {
		t.Fatal(err)
	}
	lane.Advisory = *advisory
	lane.RecordPin = advisoryRecordPin(*advisory)
	lane.Affected.Scope = advisory.Vuln.Scope.Clone()
	return lane
}

func persistRequestTestCase(t *testing.T, lane *LaneResult, dir string) {
	t.Helper()
	if err := lane.PersistRequestedCase(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "records"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "records", lane.Advisory.Input.RawSHA256+".json")
	if err := os.WriteFile(path, lane.Advisory.RawBytes, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResearchPublicationRejectsTransplantedInputs(t *testing.T) {
	for _, tc := range []struct {
		name            string
		mutate          func(*LaneResult)
		foreignAdvisory bool
		want            string
	}{
		{name: "snapshot", mutate: func(l *LaneResult) { l.Snapshot.ContentHash = strings.Repeat("cd", 32) }, want: "input.snapshot"},
		{name: "repository", mutate: func(l *LaneResult) { l.Snapshot.Repository = "/foreign" }, want: "input.snapshot"},
		{name: "commit", mutate: func(l *LaneResult) { l.Snapshot.Commit = "foreign" }, want: "input.snapshot"},
		{name: "external commit", mutate: func(l *LaneResult) { l.Snapshot.ExternalCommitSHA = "foreign" }, want: "input.snapshot"},
		{name: "goos", mutate: func(l *LaneResult) { l.Snapshot.GOOS = "windows" }, want: "input.snapshot"},
		{name: "goarch", mutate: func(l *LaneResult) { l.Snapshot.GOARCH = "arm64" }, want: "input.snapshot"},
		{name: "tags", mutate: func(l *LaneResult) { l.Snapshot.BuildTags = []string{"foreign"} }, want: "input.snapshot"},
		{name: "vendor", mutate: func(l *LaneResult) { l.Snapshot.VendorMode = true }, want: "input.snapshot"},
		{name: "workspace", mutate: func(l *LaneResult) { l.Snapshot.GoWorkFile = "/foreign/go.work" }, want: "input.snapshot"},
		{name: "toolchain", mutate: func(l *LaneResult) { l.Snapshot.GoVersion = "go1.26.0" }, want: "input.snapshot"},
		{name: "release toolchain", mutate: func(l *LaneResult) { l.Snapshot.ReleaseGoVersion = "1.26.0" }, want: "input.snapshot"},
		{name: "minimum toolchain", mutate: func(l *LaneResult) { l.Snapshot.MinimumGoVersion = "1.26" }, want: "input.snapshot"},
		{name: "version provenance", mutate: func(l *LaneResult) { l.Snapshot.GoVersionSource = domain.GoVersionSource("foreign") }, want: "input.snapshot"},
		{name: "target provenance", mutate: func(l *LaneResult) { l.Snapshot.Target = &domain.ProductTarget{GOOS: "linux", GOARCH: "amd64"} }, want: "input.snapshot"},
		{name: "release provenance", mutate: func(l *LaneResult) { l.Snapshot.ReleaseEvidenceRequired = true }, want: "input.snapshot"},
		{name: "advisory", foreignAdvisory: true, want: "input.advisory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := persistedRequestLane(t, "original")
			publishTestComposition(t, original)
			r := Assemble(AssembleInput{Lane: original, DeterministicOnly: true, StartedAt: time.Now(), FinishedAt: time.Now()})
			summary := "original"
			if tc.foreignAdvisory {
				summary = "foreign"
			}
			donor := persistedRequestLane(t, summary)
			if tc.mutate != nil {
				tc.mutate(donor)
			}
			donor.SnapshotRoot = donor.Snapshot.Repository
			donor.ContentHash = donor.Snapshot.ContentHash
			publishTestComposition(t, donor)
			if _, err := finding.Project(donor.RequestedCase); err != nil {
				t.Fatalf("donor is not independently admissible: %v", err)
			}
			r.RequestComposition = donor.RequestComposition
			r.RequestedCaseSHA256 = requestedCaseDigest(donor.RequestedCase)
			dir := t.TempDir()
			persistRequestTestCase(t, donor, dir)
			donorReport := Assemble(AssembleInput{Lane: donor, DeterministicOnly: true, StartedAt: time.Now(), FinishedAt: time.Now()})
			if err := validateRequestedCase(donorReport, dir); err != nil {
				t.Fatalf("valid donor run refused: %v", err)
			}
			if err := validateRequestedCase(r, dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("same-ID foreign case accepted or wrong refusal: %v", err)
			}
		})
	}
}

func TestResearchPublicationAdmitsCopiedRun(t *testing.T) {
	lane := persistedRequestLane(t, "original")
	publishTestComposition(t, lane)
	r := Assemble(AssembleInput{Lane: lane, DeterministicOnly: true, StartedAt: time.Now(), FinishedAt: time.Now()})
	dir := t.TempDir()
	persistRequestTestCase(t, lane, dir)
	// Copy only retained members, then remove the original advisory. Neither
	// the original source locator nor the output directory is the identity.
	copied := t.TempDir()
	if err := os.CopyFS(copied, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lane.Advisory.Input.SourcePath); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateRequestedCase(&decoded, copied); err != nil {
		t.Fatalf("valid copied run refused: %v", err)
	}
}

func TestResearchPublicationRejectsPolicyDrift(t *testing.T) {
	lane := requestLane(t, domain.ClaimFalse)
	publishTestComposition(t, lane)
	lane.RequestedCase.RequestedFinding.RequestedID = "GO-DRIFT"
	if _, err := lane.AdmitRequestComposition(nil); !errors.Is(err, ErrRequestCompositionDrift) {
		t.Fatalf("fresh publication admission: %v", err)
	}
	if err := lane.PersistRequestedCase(t.TempDir()); !errors.Is(err, ErrRequestCompositionDrift) {
		t.Fatalf("persisted stale authority: %v", err)
	}
}

func TestResearchPublicationSchemaContract(t *testing.T) {
	for name, composition := range map[string]*domain.RequestedFinding{
		"decided": validRequestComposition(t), "external": externalRequestComposition(t), "failed": failedRequestComposition(t),
	} {
		t.Run(name, func(t *testing.T) {
			r := validReport(t)
			r.Schema = ReportSchemaV5
			r.RequestComposition = composition
			r.RequestedCaseSHA256 = strings.Repeat("a", 64)
			if err := Validate(r, ""); err != nil {
				t.Fatal(err)
			}
			md, err := RenderMarkdown(r)
			if err != nil || !strings.Contains(string(md), string(composition.Outcome)) {
				t.Fatalf("canonical outcome rendering: %v", err)
			}
			r.RequestComposition = nil
			if err := Validate(r, ""); err == nil {
				t.Fatal("/5 missing composition accepted")
			}
		})
	}
	r := validReport(t)
	r.Schema = ReportSchemaV4
	r.RequestComposition = validRequestComposition(t)
	if err := Validate(r, ""); err == nil || !strings.Contains(err.Error(), "requires a decision_artifact") {
		t.Fatalf("historical /4 member contract weakened: %v", err)
	}
}

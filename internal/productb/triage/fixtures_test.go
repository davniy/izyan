package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

// goodStage0 builds a fully resolved Stage 0 fixture: confirmed intake
// fields, a matched catalog source, a bounded ref selection, a pinned
// snapshot, a frozen advisory and a package check inside the affected
// range — the state a clean run reaches before the composer.
func goodStage0() Stage0Result {
	raw := []byte(`{"vulnerability":"CVE-2099-0001","severity":"high","package":"example.org/library"}`)
	sum := sha256.Sum256(raw)
	ticketHash := hex.EncodeToString(sum[:])
	findingRaw := []byte(`{"schema_version":"finding.v1","finding_id":"finding-example-001"}`)
	fsum := sha256.Sum256(findingRaw)
	return Stage0Result{
		Raw: RawIntake{
			Raw:        raw,
			TicketHash: ticketHash,
			Format:     IntakeJSON,
		},
		Input: FindingInput{
			Finding: Finding{
				SchemaVersion: FindingSchemaVersion,
				FindingID:     "finding-example-001",
				Vulnerability: Vulnerability{IDs: []string{"CVE-2099-0001"}},
				Component:     Component{Name: "service-example", Package: "example.org/library", Version: "v1.2.3"},
				Target:        Target{Repository: "/materialized/svc", Revision: "v1.4.0"},
				Scanner:       Scanner{Severity: "high"},
			},
			Raw:    findingRaw,
			SHA256: hex.EncodeToString(fsum[:]),
		},
		Proposal: IntakeProposal{
			SchemaVersion:    IntakeProposalSchemaVersion,
			VulnerabilityIDs: []string{"CVE-2099-0001"},
			Package:          "example.org/library",
			Version:          "v1.2.3",
			Component:        "service-example",
			Severity:         "high",
		},
		Validation: IntakeValidation{Fields: []FieldValidation{
			{Field: "vulnerability_ids", Status: IntakeValid, Value: "CVE-2099-0001", Provenance: []string{"raw_text", "advisory"}},
			{Field: "package", Status: IntakeValid, Value: "example.org/library", Provenance: []string{"raw_text"}},
			{Field: "component", Status: IntakeValid, Value: "service-example", Provenance: []string{"catalog"}},
			{Field: "severity", Status: IntakeValid, Value: "high", Provenance: []string{"raw_text"}},
		}},
		CatalogEntry: CatalogEntry{ID: "service-example", Kind: "local", Root: "/src/service-example", Ecosystem: "go"},
		CandidateRefs: []RefCandidate{
			{ID: "cand-1", Name: "v1.4.0", Kind: RefTag, Commit: strings.Repeat("ab", 20), Source: "service-example"},
		},
		SelectedRef: RefCandidate{ID: "cand-1", Name: "v1.4.0", Kind: RefTag, Commit: strings.Repeat("ab", 20), Source: "service-example"},
		RefResolution: RefResolution{
			SelectedID: "cand-1", SelectedRef: "v1.4.0",
			ResolvedCommit: strings.Repeat("ab", 20), ResolutionRule: RefRuleExact,
			SelectionProvenance: RefProvenanceFallback,
		},
		Source: MaterializedSource{
			Root: "/materialized/svc",
			Metadata: MaterializationMetadata{
				Mode: MaterializationLocal, SourceID: "service-example",
				SelectedRef: "v1.4.0", ResolvedCommit: strings.Repeat("ab", 20),
				RootHash: strings.Repeat("cd", 32), CreatedAt: "2026-10-16T00:00:00Z",
			},
		},
		Snapshot: SnapshotManifest{
			SchemaVersion:    SnapshotSchemaVersion,
			FindingID:        "finding-example-001",
			Repository:       "/materialized/svc",
			Revision:         "v1.4.0",
			ResolvedRevision: strings.Repeat("ab", 20),
			RevisionStatus:   FactValid,
			ContentHash:      strings.Repeat("cd", 32),
			InputHash:        hex.EncodeToString(fsum[:]),
			CreatedAt:        "2026-10-16T00:00:00Z",
		},
		Materials: MaterialSet{
			ModuleGraph: &ModuleGraph{
				Source:   "go list -m all",
				Complete: true,
				Modules:  []ModuleVersion{{Path: "example.org/library", Version: "v1.2.3"}},
			},
			Deploy: &DeployFacts{
				FactCount:    1,
				Perimeter:    domain.PerimeterClusterInternal,
				ScannedPaths: []string{"deploy"},
			},
		},
		Advisory: vulnerability.FrozenAdvisory{
			SchemaVersion: vulnerability.FrozenAdvisorySchemaVersion,
			ID:            "CVE-2099-0001",
			ResolvedID:    "CVE-2099-0001",
			Source:        vulnerability.AdvisoryFrozenOSV,
			Path:          "advisory/CVE-2099-0001.json",
			SHA256:        strings.Repeat("ef", 32),
		},
		Resolution: &AdvisoryResolution{
			Vulnerability: &domain.Vulnerability{
				ID:               "CVE-2099-0001",
				Module:           "example.org/library",
				BaseSeverity:     "HIGH",
				SeveritySource:   "OSV",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "v1.2.4"}},
			},
			Projection: AdvisoryProjection{
				Module:           "example.org/library",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "v1.2.4"}},
			},
			Record: vulnerability.FrozenAdvisory{
				SchemaVersion: vulnerability.FrozenAdvisorySchemaVersion,
				ID:            "CVE-2099-0001",
				ResolvedID:    "CVE-2099-0001",
				Source:        vulnerability.AdvisoryFrozenOSV,
				Path:          "advisory/CVE-2099-0001.json",
				SHA256:        strings.Repeat("ef", 32),
			},
		},
		PackageCheck: PackageCheckResult{
			Class:           CheckAffectedRange,
			ClaimedPath:     "example.org/library",
			ClaimedVersion:  "v1.2.3",
			ResolvedPath:    "example.org/library",
			ResolvedVersion: "v1.2.3",
			EvidenceSource:  "module_graph",
			Reason:          "example.org/library@v1.2.3 is inside an advisory affected range",
			Provenance:      []string{"go list -m all"},
		},
		ReleaseToolchain: ReleaseToolchainFact{
			Version:  "1.25.8",
			Source:   domain.GoVersionSourceBinary,
			Location: "bin/service-example",
		},
		Toolchain:  toolchain.Toolchain{Version: "1.25.8", Mode: toolchain.ModeSDK, GoBin: "go"},
		ConfigHash: strings.Repeat("01", 32),
	}
}

// goodAssessment is a clean agent result: a terminal verdict plus a cited,
// verified claim — never policy fields.
func goodAssessment() Assessment {
	return Assessment{
		SchemaVersion: AssessmentSchemaVersion,
		FindingID:     "finding-example-001",
		Verdict:       VerdictNotExploitable,
		Summary:       "vulnerable code is not reachable in this build",
		Claims: []Claim{
			{
				ID:               "c1",
				Statement:        "module example.org/library is not in the build graph",
				Basis:            PremiseMeasured,
				Subject:          "example.org/library build-graph membership",
				Scope:            "recorded module graph",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"ev-1"},
				Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-1"},
			},
		},
		Evidence: []EvidenceRef{{ID: "ev-1", Kind: "det", Locator: "det:obs-1"}},
		ProposedAction: HumanAction{
			Kind:             HumanActionClose,
			Instruction:      "close the ticket as not exploitable",
			Rationale:        "the affected module is absent from the recorded build graph",
			Scope:            "the captured product build",
			RecordIDs:        []string{"CVE-2099-0001"},
			DecisiveClaimIDs: []string{"c1"},
			ReconsiderWhen:   []string{"the module appears in the recorded build graph"},
		},
		Audit: &AssessmentAudit{PromptHash: strings.Repeat("09", 32)},
	}
}

// closeAction is a structurally valid CLOSE proposal over the named
// decisive claims — the default ProposedAction for assessment fixtures.
func closeAction(claimIDs ...string) HumanAction {
	return HumanAction{
		Kind:             HumanActionClose,
		Instruction:      "close the ticket as not exploitable",
		Rationale:        "the decisive claims establish that the captured build is not affected",
		Scope:            "captured product build",
		DecisiveClaimIDs: claimIDs,
		ReconsiderWhen:   []string{"new evidence contradicts a decisive claim"},
	}
}

// declaredProofProposal is the proposal a fixture proof answers. The
// certificate contract binds every non-checker proof to a persisted
// proposal, so a report whose proposal the assessment does not declare is
// malformed material — the composer rejects it instead of accepting the
// proof silently.
func declaredProofProposal(id, claimID, conditionID string) FalsifierProposal {
	return FalsifierProposal{
		ID: id, ClaimID: claimID, ConditionID: conditionID, Kind: FalsifierCodeAbsent,
		Subjects:     []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}},
		EvidenceRefs: []string{"ev-1"},
	}
}

// assessmentWithProposal declares the given proposal on the assessment.
func assessmentWithProposal(a Assessment, p FalsifierProposal) Assessment {
	a.FalsifierProposals = append(a.FalsifierProposals, p)
	return a
}

// completeValidation is the clean fact gate report every matrix row
// starts from.
func completeValidation() FactValidation {
	return FactValidation{
		Status: ValidationComplete,
		References: []ReferenceCheck{{
			EvidenceID: "ev-1", Status: FactValid, Subject: "det:obs-1",
			Scope: "observation", SnapshotHash: strings.Repeat("cd", 32),
		}},
	}
}

// composeOrFail composes with the default providers and auto-run checks.

func noSeverityStage0() Stage0Result {
	s0 := goodStage0()
	s0.Resolution.Vulnerability.BaseSeverity = ""
	s0.Resolution.Vulnerability.BaseScore = 0
	s0.Proposal.Severity = ""
	s0.Input.Finding.Scanner.Severity = ""
	for i := range s0.Validation.Fields {
		if s0.Validation.Fields[i].Field == "severity" {
			s0.Validation.Fields[i].Status = IntakeUnavailable
			s0.Validation.Fields[i].Provenance = nil
		}
	}
	return s0
}

func hasLimitationContaining(lims []string, sub string) bool {
	for _, l := range lims {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func hasFact(facts []DecisionFact, kind, status string) bool {
	for _, f := range facts {
		if f.Kind == kind && f.Status == status {
			return true
		}
	}
	return false
}

// TestDemotionRules covers the demotion contract: DISMISSED/LOWERED are
// unreachable while any decision-relevant fact or check is short of
// verified.

func replaceCheck(in []CheckResult, id string, st CheckStatus) []CheckResult {
	out := append([]CheckResult(nil), in...)
	for i := range out {
		if out[i].ID == id {
			out[i].Status = st
			out[i].Reasons = []string{"test-injected"}
		}
	}
	return out
}

// replayClockA/replayClockB are the deterministic clocks artifact tests
// share (ported from V2 replay_test.go — replay.go itself is not ported).
var (
	replayClockA = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
	replayClockB = func() time.Time { return time.Date(2026, 10, 16, 18, 30, 0, 0, time.UTC) }
)

// versionRangeStage0 is the resolved-stage0 fixture the version-range
// tests mutate: a frozen advisory, a matched module and a package check
// whose class the caller picks.
func versionRangeStage0(class PackageCheckClass) Stage0Result {
	s0 := goodStage0()
	record := vulnerability.FrozenAdvisory{
		SchemaVersion: vulnerability.FrozenAdvisorySchemaVersion,
		ID:            "CVE-2099-0001",
		ResolvedID:    "CVE-2099-0001",
		Source:        vulnerability.AdvisoryFrozenOSV,
		SHA256:        strings.Repeat("ab", 32),
	}
	s0.Advisory = record
	s0.Resolution = &AdvisoryResolution{
		Record:        record,
		Vulnerability: &domain.Vulnerability{ID: "CVE-2099-0001"},
		Projection: AdvisoryProjection{
			Module:  "example.org/library",
			Package: "example.org/library",
			AffectedVersions: []domain.VersionRange{
				{Introduced: "0", Fixed: "1.3.0"},
			},
			FixedVersions: []string{"1.3.0"},
		},
	}
	s0.PackageCheck = PackageCheckResult{
		Class:           class,
		ClaimedPath:     "example.org/library",
		ClaimedVersion:  "v1.4.2",
		ResolvedPath:    "example.org/library",
		ResolvedVersion: "v1.4.2",
		EvidenceSource:  "module_graph",
		Provenance:      []string{"vendor/modules.txt"},
	}
	return s0
}

// supportObservation is the recorded tool observation the support tests
// cite: a completed, digest-pinned, snapshot-bound deterministic result
// whose payload states exactly one narrow fact.
func supportObservation(t *testing.T, s0 Stage0Result, id, fact string, attempt int) RecordedObservation {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":           id,
		"tool":         "verify_package_absence",
		"fact":         fact,
		"scope":        "snapshot",
		"completeness": string(evidencetools.CompletenessComplete),
		"tool_status":  "OK",
	})
	if err != nil {
		t.Fatalf("marshal support observation: %v", err)
	}
	sum := sha256.Sum256(payload)
	return RecordedObservation{
		ID:           id,
		Tool:         "verify_package_absence",
		Status:       ToolStatusOK,
		Completeness: evidencetools.CompletenessComplete,
		Scope:        "snapshot",
		Payload:      payload,
		DataSHA256:   hex.EncodeToString(sum[:]),
		SnapshotHash: s0.Snapshot.ContentHash,
		Attempt:      attempt,
	}
}

// supportProof is the admitted checker proof and the proposal it answers:
// a VERIFIED locus_package_absent certificate bound to the fixture
// snapshot, condition and subject set. It exercises the existing report and
// certificate validators rather than a bespoke support-only shape.
func supportProof(t *testing.T, s0 Stage0Result, claimID string) (FalsifierProposal, FalsifierReport) {
	t.Helper()
	subjects := []FalsifierSubject{{Package: "example.org/library", Symbol: "Vulnerable"}}
	proof := FalsifierProof{
		ID:           "fp-1",
		ProposalID:   "fp-1",
		ClaimID:      claimID,
		ConditionID:  "cond-1",
		Kind:         FalsifierLocusPackageAbsent,
		Status:       FalsifierVerified,
		Basis:        BasisCheckerVerified,
		Mandatory:    true,
		RuleID:       "rule-1",
		RuleVersion:  "v1",
		Falsifier:    "package absence",
		EvidenceRefs: []string{"ev-1"},
		Coverage: FalsifierCoverage{
			Scope:            "snapshot",
			Completeness:     string(evidencetools.CompletenessComplete),
			SnapshotHash:     s0.Snapshot.ContentHash,
			BuildContextHash: "build-1",
			ExpectedSubjects: subjects,
			CheckedSubjects:  subjects,
			AbsentSubjects:   subjects,
		},
		Reason: "package is absent from the recorded build graph",
	}
	proposal := FalsifierProposal{
		ID:           "fp-1",
		ClaimID:      claimID,
		ConditionID:  "cond-1",
		Kind:         FalsifierLocusPackageAbsent,
		Subjects:     subjects,
		EvidenceRefs: []string{"ev-1"},
	}
	return proposal, NewFalsifierReport("rules-1", proof)
}

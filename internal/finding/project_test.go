package finding_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/finding"
	"github.com/davniy/izyan/internal/goanalysis"
	"github.com/davniy/izyan/internal/rootcause"
)

const (
	projectCVE         = "CVE-2023-44487"
	projectPrimary     = "GHSA-qppj-fm5r-hxr3"
	projectChild       = "GO-2023-2153"
	projectPrimaryCase = domain.CaseID("project-primary")
	projectChildCase   = domain.CaseID("project-child")
)

func projectAffected(c *domain.AnalysisCase) domain.AffectedResult {
	if c.Affected != nil {
		return *c.Affected
	}
	return domain.AffectedResult{}
}

func projectModel(c *domain.AnalysisCase) domain.ExploitModel {
	if c.Exploit != nil {
		return *c.Exploit
	}
	return domain.ExploitModel{}
}

// projectAssess classifies a synthetic record exactly as the workflow does,
// so a saved fixture is a genuine Task 5 result rather than a hand assertion.
func projectAssess(c *domain.AnalysisCase, claims []domain.Claim) domain.AssessmentResult {
	return finding.Assess(finding.AssessmentInput{
		VerdictInput: evaluator.VerdictInput{
			Product:  c.Product,
			Affected: projectAffected(c),
			Model:    projectModel(c),
			Claims:   claims,
			Evidence: c.EvidenceGraph.EvidenceList(),
			RecordPin: c.RecordPin,
			AdvisoryRecord: c.AdvisoryRecord,
		},
		RootCause:    c.RootCause,
		AssessmentID: c.ID,
	})
}

func projectAddEvidence(c *domain.AnalysisCase, ids ...domain.EvidenceID) {
	for _, id := range ids {
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:      id,
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "projection-test",
			Content: string(id),
		})
	}
}

// projectPositiveRecord builds one independently earned library-API positive.
// The library boundary is a mandatory claim basis, so the recomputed verdict
// carries condition and evidence references without needing a transport
// witness fixture.
func projectPositiveRecord(t *testing.T, id domain.CaseID, recordID string) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(recordID)
	claims := []domain.Claim{{
		ID:           "CL-C-API",
		ConditionID:  "C-API",
		Result:       domain.ClaimTrue,
		EvidenceIDs:  []domain.EvidenceID{"EV-API"},
		ControlBasis: domain.ControlBasisLibraryPublicAPI,
	}}
	c := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   recordID,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: composeScope(recordID, domain.ScopeAdvisoryEntries, domain.CoverageComplete)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected:      &domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue},
		Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
			ID: "C-API", Kind: domain.ConditionInputConstraint, Mandatory: true,
		}}},
		Claims: claims,
	}
	projectAddEvidence(c, "EV-API")
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         projectAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize %q: %v", id, err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// projectFailedRecord builds a record whose own assessment could not earn a
// verdict; the diagnostics make it a valid FAILED result.
func projectFailedRecord(t *testing.T, id domain.CaseID, recordID string) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(recordID)
	c := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   recordID,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: composeScope(recordID, domain.ScopeAdvisoryEntries, domain.CoverageComplete)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         projectAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize %q: %v", id, err)
	}
	c.Workflow.State = domain.StateFailed
	return c
}

// projectCVEPositive builds a CVE request whose primary failed and whose one
// independently attributed related record earned the positive.
func projectCVEPositive(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	primaryPin := composePin(projectPrimary)
	child := projectPositiveRecord(t, projectChildCase, projectChild)
	childPin := composePin(projectChild)
	root := &domain.AnalysisCase{
		ID:            projectPrimaryCase,
		RequestedID:   projectCVE,
		Vulnerability: domain.Vulnerability{ID: projectPrimary, Scope: composeScope(projectCVE, domain.ScopeCVE, domain.CoverageKnownOnly)},
		RecordPin:     &primaryPin,
		Product:       composeProduct(build),
		ProfileAssessments: []domain.ProfileAssessment{{
			Profile:        domain.ProfileZeroTrust,
			IsTargetActual: true,
			Build:          build,
			Result:         projectAssess(&domain.AnalysisCase{ID: projectPrimaryCase}, nil),
		}},
		RelatedDiscovery: &domain.RelatedDiscovery{
			RequestedID: projectCVE,
			Enumeration: domain.DiscoveryPartial,
			Corpus:      &domain.CorpusReference{Reference: "osv-dump", Digest: composeDigest("corpus"), CapturedAt: "2026-10-20"},
			Candidates: []domain.DiscoveryCandidate{{
				Record:      childPin,
				Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: projectCVE}},
				Disposition: domain.DispositionEvaluated,
			}},
		},
		RelatedRecords: []domain.RelatedRecordAssessment{{
			ID: child.ID, Record: childPin, Analysis: child,
		}},
		Attributions: []domain.CVEAttribution{composeAttribution("ATTR-CHILD", childPin)},
	}
	if err := finding.Finalize(root); err != nil {
		t.Fatalf("finalize cve root: %v", err)
	}
	root.Workflow.State = domain.StateCompleted
	return root
}

// projectCorpusNegative builds a declared-corpus CVE negative. The basis and
// its manifest digest are derived, so a later manifest mutation is observable
// as policy drift.
func projectCorpusNegative(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	primaryPin := composePin(projectPrimary)
	child := &domain.AnalysisCase{
		ID:            projectChildCase,
		RequestedID:   projectChild,
		Vulnerability: domain.Vulnerability{ID: projectChild, Scope: composeScope(projectChild, domain.ScopeAdvisoryEntries, domain.CoverageComplete)},
		Product:       composeProduct(build),
		Affected:      &domain.AffectedResult{Scope: outcomeScope(projectChild), ModulePresent: domain.ClaimFalse},
	}
	childPin := composePin(projectChild)
	child.RecordPin = &childPin
	child.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         projectAssess(child, nil),
	}}
	if err := finding.Finalize(child); err != nil {
		t.Fatalf("finalize negative child: %v", err)
	}
	child.Workflow.State = domain.StateCompleted

	reference := "osv-dump-2026-10-20"
	digest := composeDigest("declared-corpus")
	manifest := domain.CorpusManifest{
		Reference:      reference,
		CapturedAt:     "2026-10-20",
		ObservedDigest: digest,
		Enumeration:    domain.DiscoveryFinished,
		Documents:      []domain.RecordPin{childPin},
		Sources:        []domain.CorpusSource{{Ref: "https://osv.dev/dump", SHA256: composeDigest("source"), CheckedAt: "2026-10-20"}},
	}
	root := &domain.AnalysisCase{
		ID:            projectPrimaryCase,
		RequestedID:   projectCVE,
		Vulnerability: domain.Vulnerability{ID: projectPrimary, Scope: composeScope(projectCVE, domain.ScopeCVE, domain.CoverageKnownOnly)},
		RecordPin:     &primaryPin,
		Product:       composeProduct(build),
		ProfileAssessments: []domain.ProfileAssessment{{
			Profile:        domain.ProfileZeroTrust,
			IsTargetActual: true,
			Build:          build,
			Result:         projectAssess(&domain.AnalysisCase{ID: projectPrimaryCase}, nil),
		}},
		CorpusDeclaration: &domain.CorpusDeclaration{Reference: reference, ExpectedDigest: digest, CapturedAt: "2026-10-20"},
		CorpusManifest:    &manifest,
		RelatedDiscovery: &domain.RelatedDiscovery{
			RequestedID: projectCVE,
			Enumeration: domain.DiscoveryFinished,
			Corpus:      &domain.CorpusReference{Reference: reference, Digest: digest, CapturedAt: "2026-10-20"},
			Candidates: []domain.DiscoveryCandidate{{
				Record:      childPin,
				Edges:       []domain.DiscoveryEdge{{Kind: domain.RelationRelated, ID: projectCVE}},
				Disposition: domain.DispositionEvaluated,
			}},
		},
		RelatedRecords: []domain.RelatedRecordAssessment{{ID: child.ID, Record: childPin, Analysis: child}},
	}
	if err := finding.Finalize(root); err != nil {
		t.Fatalf("finalize corpus negative: %v", err)
	}
	root.Workflow.State = domain.StateCompleted
	return root
}

func projectClone(t *testing.T, c *domain.AnalysisCase) *domain.AnalysisCase {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal case: %v", err)
	}
	var out domain.AnalysisCase
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal case: %v", err)
	}
	return &out
}

func TestFindingProjectionAdmission(t *testing.T) {
	t.Run("an exact positive projects its admitted witness", func(t *testing.T) {
		c := projectPositiveRecord(t, projectPrimaryCase, projectPrimary)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		if view.Primary != c {
			t.Fatal("projection did not retain the primary assessment")
		}
		if view.Requested.Status != domain.FindingFinal || view.Requested.Outcome != domain.OutcomeDecided ||
			view.Requested.Verdict != domain.VerdictExploitable {
			t.Fatalf("requested = %+v", view.Requested.FindingProfile)
		}
		if len(view.Records) != 1 || view.Records[c.ID] != c {
			t.Fatalf("records = %+v", view.Records)
		}
		if len(view.Witnesses) != 1 {
			t.Fatalf("witnesses = %+v", view.Witnesses)
		}
		witness := view.Witnesses[0]
		if witness.Assessment != c || witness.Origin.AssessmentID != c.ID {
			t.Fatalf("witness = %+v", witness)
		}
		if witness.Origin.Record.RecordID != projectPrimary || witness.Profile.Profile != domain.ProfileZeroTrust {
			t.Fatalf("witness origin/profile = %+v/%+v", witness.Origin, witness.Profile)
		}
		if len(witness.Origin.EvidenceRefs) == 0 || len(witness.Origin.ConditionRefs) == 0 {
			t.Fatalf("witness carries no qualified references: %+v", witness.Origin)
		}
		for _, ref := range witness.Origin.EvidenceRefs {
			if ref.AssessmentID != c.ID {
				t.Fatalf("evidence ref is not qualified to the assessment: %+v", ref)
			}
		}
	})

	t.Run("a CVE positive keeps the child assessment and attribution pins", func(t *testing.T) {
		c := projectCVEPositive(t)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeDecided || view.Requested.Verdict != domain.VerdictExploitable {
			t.Fatalf("requested = %s/%q gaps=%+v", view.Requested.Outcome, view.Requested.Verdict, view.Requested.Gaps)
		}
		if len(view.Requested.ProofOrigins) != 1 || view.Requested.ProofOrigins[0].AssessmentID != projectChildCase {
			t.Fatalf("origins = %+v", view.Requested.ProofOrigins)
		}
		if len(view.Records) != 2 || view.Records[projectPrimaryCase] != c ||
			view.Records[projectChildCase] == nil {
			t.Fatalf("records = %+v", view.Records)
		}
		if len(view.Witnesses) != 1 || view.Witnesses[0].Origin.AttributionID != "ATTR-CHILD" {
			t.Fatalf("witnesses = %+v", view.Witnesses)
		}
	})

	t.Run("a composed envelope is publishable before the terminal state", func(t *testing.T) {
		c := projectCVEPositive(t)
		// The pipeline composes and finalizes the envelope, then runs
		// BUILD_REPORT, and only afterwards reaches COMPLETED/FAILED. Both the
		// root and its finalized child must be publishable at this position.
		c.Workflow.State = domain.StateBuildReport
		c.RelatedRecords[0].Analysis.Workflow.State = domain.StateBuildReport
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project at BUILD_REPORT: %v", err)
		}
		if view.Requested.Status != domain.FindingFinal ||
			view.Requested.Outcome != domain.OutcomeDecided {
			t.Fatalf("requested = %+v", view.Requested.FindingProfile)
		}
	})

	t.Run("a PENDING v2 envelope is refused before the terminal state", func(t *testing.T) {
		c := projectPositiveRecord(t, projectPrimaryCase, projectPrimary)
		c.Workflow.State = domain.StateBuildReport
		c.RequestedFinding = &domain.RequestedFinding{
			Status:              domain.FindingPending,
			RequestedID:         c.RequestedID,
			RequestedKind:       domain.ScopeAdvisoryEntries,
			Coverage:            domain.CoverageComplete,
			PrimaryAssessmentID: c.ID,
		}
		view, err := finding.Project(c)
		if err == nil || !strings.Contains(err.Error(), "not publishable") {
			t.Fatalf("err = %v, want a not-publishable refusal", err)
		}
		if view.Requested.Status != "" {
			t.Fatalf("a PENDING envelope produced a publication: %+v", view)
		}
	})

	t.Run("a failed request remains publishable with its diagnostics", func(t *testing.T) {
		c := projectFailedRecord(t, projectPrimaryCase, projectPrimary)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project failed request: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeFailed || view.Requested.Verdict != "" {
			t.Fatalf("requested = %s/%q", view.Requested.Outcome, view.Requested.Verdict)
		}
		if len(view.Requested.Gaps) == 0 {
			t.Fatal("a failed result must keep its typed diagnostics")
		}
		if len(view.Witnesses) != 0 {
			t.Fatalf("a failure published witnesses: %+v", view.Witnesses)
		}
	})

	t.Run("an external dependency remains publishable", func(t *testing.T) {
		build := composeBuild()
		pin := composePin(projectPrimary)
		c := &domain.AnalysisCase{
			ID:            projectPrimaryCase,
			RequestedID:   projectPrimary,
			Vulnerability: domain.Vulnerability{ID: projectPrimary, Scope: composeScope(projectPrimary, domain.ScopeAdvisoryEntries, domain.CoverageComplete)},
			RecordPin:     &pin,
			Product:       composeProduct(build),
			Affected: &domain.AffectedResult{
				ModulePresent:   domain.ClaimTrue,
				VersionAffected: domain.ClaimUnknown,
				EvidenceIDs:     []domain.EvidenceID{"EV-VERSION"},
			},
		}
		projectAddEvidence(c, "EV-VERSION")
		c.ProfileAssessments = []domain.ProfileAssessment{{
			Profile:        domain.ProfileZeroTrust,
			IsTargetActual: true,
			Build:          build,
			Result:         projectAssess(c, nil),
		}}
		if err := finding.Finalize(c); err != nil {
			t.Fatalf("finalize external: %v", err)
		}
		c.Workflow.State = domain.StateCompleted
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project external request: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeExternal || len(view.Requested.ExternalDependencies) != 1 {
			t.Fatalf("requested = %+v", view.Requested.FindingProfile)
		}
	})

	t.Run("a corpus negative re-derives its manifest basis", func(t *testing.T) {
		c := projectCorpusNegative(t)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project corpus negative: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeDecided || view.Requested.Verdict != domain.VerdictNotAffected {
			t.Fatalf("requested = %s/%q", view.Requested.Outcome, view.Requested.Verdict)
		}
		if view.Requested.CorpusNegativeBasis == nil || view.Requested.CorpusNegativeBasis.ManifestDigest == "" {
			t.Fatalf("basis = %+v", view.Requested.CorpusNegativeBasis)
		}
	})

	t.Run("legacy cases are refused without inventing a projection", func(t *testing.T) {
		legacy := &domain.AnalysisCase{
			ID:            "legacy-case",
			Vulnerability: domain.Vulnerability{ID: "GO-2020-0001"},
			Workflow:      domain.WorkflowStatus{State: domain.StateCompleted},
			Verdict:       &domain.VerdictResult{Verdict: domain.VerdictInconclusive, Reason: "historical"},
		}
		view, err := finding.Project(legacy)
		if !errors.Is(err, finding.ErrLegacyCase) {
			t.Fatalf("err = %v, want ErrLegacyCase", err)
		}
		var legacyErr *finding.LegacyCaseError
		if !errors.As(err, &legacyErr) || legacyErr.Pending {
			t.Fatalf("legacy error = %+v", err)
		}
		if view.Requested.Status != "" || view.Requested.Outcome != "" || len(view.Witnesses) != 0 {
			t.Fatalf("legacy case acquired a projection: %+v", view)
		}
		if legacy.RequestedFinding != nil || legacy.RelatedDiscovery != nil || len(legacy.Attributions) != 0 {
			t.Fatal("projection invented discovery, attribution or a requested finding")
		}
	})

	t.Run("a pending new-contract case is not publishable", func(t *testing.T) {
		pending := &domain.AnalysisCase{
			ID:            "pending-root",
			RequestedID:   projectCVE,
			Vulnerability: domain.Vulnerability{ID: projectPrimary},
			Workflow:      domain.WorkflowStatus{State: domain.StateAssessRelatedRecords},
			RelatedDiscovery: &domain.RelatedDiscovery{
				RequestedID: projectCVE,
				Enumeration: domain.DiscoveryPartial,
			},
		}
		_, err := finding.Project(pending)
		var legacyErr *finding.LegacyCaseError
		if !errors.As(err, &legacyErr) || !legacyErr.Pending {
			t.Fatalf("err = %v, want a pending LegacyCaseError", err)
		}
	})

	t.Run("an operator-demoted NEPF remains a publishable failure", func(t *testing.T) {
		build := composeBuild()
		pin := composePin(projectPrimary)
		model := domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-PEER", Kind: domain.ConditionAttackerControl, Mandatory: true,
			}},
			UnresolvedSubjects: []domain.SymbolRef{{Package: "example.com/product", Symbol: "Sink"}},
		}
		claims := []domain.Claim{{
			ID:             "CL-C-PEER",
			ConditionID:    "C-PEER",
			Result:         domain.ClaimFalse,
			Falsifier:      domain.FalsifierTrustedInfrastructure,
			FalsifierBasis: domain.BasisDeclaredTrust,
			NegativeVerification: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Notes:  "operator-declared trusted perimeter",
			},
		}}
		c := &domain.AnalysisCase{
			ID:            projectPrimaryCase,
			RequestedID:   projectPrimary,
			Vulnerability: domain.Vulnerability{ID: projectPrimary, Scope: composeScope(projectPrimary, domain.ScopeAdvisoryEntries, domain.CoverageComplete)},
			RecordPin:     &pin,
			Product:       composeProduct(build),
			Affected:      &domain.AffectedResult{Scope: outcomeScope(projectPrimary)},
			Exploit:       &model,
			Claims:        claims,
		}
		c.Product.TrustedPeer = true
		c.ProfileAssessments = []domain.ProfileAssessment{{
			Profile:        domain.ProfileZeroTrust,
			IsTargetActual: true,
			Build:          build,
			Claims:         claims,
			Result: domain.AssessmentResult{
				Outcome: domain.OutcomeFailed,
				Gaps: []domain.AnalysisGap{{
					Owner:        domain.GapOwnerCode,
					Code:         domain.GapReachabilityProofIncomplete,
					Obligation:   domain.ObligationCondition,
					AssessmentID: c.ID,
					Message:      "operator assertion cannot discharge an unmodeled exploit shape",
				}},
			},
		}}
		if err := finding.Finalize(c); err != nil {
			t.Fatalf("finalize demoted failure: %v", err)
		}
		c.Workflow.State = domain.StateFailed
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project demoted failure: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeFailed {
			t.Fatalf("requested = %s/%q", view.Requested.Outcome, view.Requested.Verdict)
		}

		withoutOperator := projectClone(t, c)
		withoutOperator.Product.TrustedPeer = false
		if _, err := finding.Project(withoutOperator); err == nil {
			t.Fatal("a saved failure without the operator trust basis hid a recomputed NEPF")
		}
	})

	t.Run("replay is refused when a historical closure no longer re-admits", func(t *testing.T) {
		c := projectCorpusNegative(t)
		c.EvidenceGraph.AddLimitation("calibration rule changed after the closure was saved")
		_, err := finding.Project(c)
		if !errors.Is(err, finding.ErrPolicyDrift) {
			t.Fatalf("err = %v, want ErrPolicyDrift", err)
		}
		var drift *finding.PolicyDriftError
		if !errors.As(err, &drift) {
			t.Fatalf("err = %v, want PolicyDriftError", err)
		}
		if !reflect.DeepEqual(drift.Saved, *c.RequestedFinding) {
			t.Fatal("drift does not carry the saved envelope")
		}
		if len(drift.Fields) == 0 {
			t.Fatal("drift names no differing field")
		}
	})

	t.Run("projection is pure and does not rewrite the saved case", func(t *testing.T) {
		c := projectCVEPositive(t)
		before, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := finding.Project(c); err != nil {
			t.Fatalf("project: %v", err)
		}
		after, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("Project mutated the persisted case")
		}
	})

	t.Run("tampered proof artifacts never publish a conclusion", func(t *testing.T) {
		mutations := []struct {
			name   string
			build  func(t *testing.T) *domain.AnalysisCase
			mutate func(t *testing.T, c *domain.AnalysisCase)
		}{
			{
				name: "record digest",
				build: func(t *testing.T) *domain.AnalysisCase {
					return projectPositiveRecord(t, projectPrimaryCase, projectPrimary)
				},
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					c.RecordPin.DocumentDigest = composeDigest("tampered-record-bytes")
				},
			},
			{
				name:  "source capture digest",
				build: projectCorpusNegative,
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					c.CorpusManifest.Sources = append(c.CorpusManifest.Sources, domain.CorpusSource{
						Ref: "https://osv.dev/tampered", SHA256: composeDigest("tampered-source"), CheckedAt: "2026-10-26",
					})
				},
			},
			{
				name:  "attribution pin",
				build: projectCVEPositive,
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					c.Attributions[0].Candidate = composePin("GO-2024-DECOY")
				},
			},
			{
				name:  "child claim",
				build: projectCVEPositive,
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					child := c.RelatedRecords[0].Analysis
					child.ProfileAssessments[0].Claims[0].Result = domain.ClaimUnknown
				},
			},
			{
				name:  "evidence reference",
				build: projectCVEPositive,
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					child := c.RelatedRecords[0].Analysis
					child.ProfileAssessments[0].Result.Verdict.EvidenceIDs = []domain.EvidenceID{"EV-FORGED"}
				},
			},
			{
				name:  "profile",
				build: projectCVEPositive,
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					child := c.RelatedRecords[0].Analysis
					child.ProfileAssessments[0].Profile = domain.ProfileClusterPerimeter
				},
			},
			{
				name:  "build",
				build: projectCVEPositive,
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					child := c.RelatedRecords[0].Analysis
					child.ProfileAssessments[0].Build.GOARCH = "arm64"
				},
			},
			{
				name:  "child record pin",
				build: projectCVEPositive,
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					child := c.RelatedRecords[0].Analysis
					child.RecordPin.DocumentDigest = composeDigest("tampered-child-bytes")
				},
			},
			{
				name: "saved envelope without artifacts",
				build: func(t *testing.T) *domain.AnalysisCase {
					return projectPositiveRecord(t, projectPrimaryCase, projectPrimary)
				},
				mutate: func(_ *testing.T, c *domain.AnalysisCase) {
					c.ProfileAssessments[0].Result = domain.AssessmentResult{
						Outcome: domain.OutcomeFailed,
						Gaps: []domain.AnalysisGap{{
							Owner:        domain.GapOwnerProof,
							Code:         domain.GapReachabilityProofIncomplete,
							Obligation:   domain.ObligationCondition,
							AssessmentID: c.ID,
							Message:      "artifacts were discarded",
						}},
					}
				},
			},
		}
		for _, tc := range mutations {
			t.Run(tc.name, func(t *testing.T) {
				c := tc.build(t)
				if _, err := finding.Project(c); err != nil {
					t.Fatalf("baseline case does not publish: %v", err)
				}
				tampered := projectClone(t, c)
				tc.mutate(t, tampered)
				view, err := finding.Project(tampered)
				if err == nil {
					t.Fatalf("tampered %s published: %+v", tc.name, view.Requested.FindingProfile)
				}
				if view.Requested.Status != "" || view.Requested.Outcome != "" || len(view.Witnesses) != 0 {
					t.Fatalf("tampered %s returned a partial publication: %+v", tc.name, view)
				}
			})
		}
	})
}

// projectAbsentCandidateRecord builds a DECIDED / NO_EXPLOIT_PATH_FOUND record
// whose negative rests on a fix-derived candidate's package being absent from
// the product build graph. The candidate's version binding is supplied by the
// caller, so the caller controls whether the subject's identity is established.
func projectAbsentCandidateRecord(t *testing.T, binding *domain.CandidateBinding,
	origin domain.RootCauseOrigin) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(projectPrimary)
	subj := domain.SymbolRef{
		Package: "github.com/containerd/containerd/cmd/containerd/server",
		Symbol:  "CreateTopLevelDirectories",
	}
	product := composeProduct(build)
	product.Target = &domain.ProductTarget{
		GOOS: build.GOOS, GOARCH: build.GOARCH,
		Source:          domain.ProductTargetSourceArtifactBuildInfo,
		Scope:           domain.ProductTargetScopeArtifact,
		ArtifactSHA256:  strings.Repeat("a", 64),
		BuildInfoSHA256: strings.Repeat("b", 64),
	}
	effective := domain.EffectiveBuildContext(product)
	inventory := domain.Evidence{
		ID:           "EV-PKGS",
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		Tool:         "go",
		Source:       "go list -deps -test -json ./...",
		Command:      "go list -deps -test -json ./...",
		Content:      `{"ImportPath":"github.com/kubernetes/kubernetes"}`,
		BuildContext: &effective,
		PackageList: &domain.PackageListRun{
			Completed: true, Complete: true, WithTests: true, Pattern: "./...",
		},
	}
	claims := []domain.Claim{{
		ID:          "CL-C-REACH",
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierPackageAbsent,
		EvidenceIDs: []domain.EvidenceID{"EV-PKGS"},
		Producer:    "evaluator.SymbolReachable",
		NegativeVerification: &domain.NegativeVerification{
			Status:       domain.NegativeVerified,
			EvidenceIDs:  []domain.EvidenceID{"EV-PKGS"},
			BuildContext: &effective,
		},
	}}
	c := &domain.AnalysisCase{
		ID:            projectPrimaryCase,
		RequestedID:   projectPrimary,
		Vulnerability: domain.Vulnerability{ID: projectPrimary, Scope: outcomeScope(projectPrimary), Module: "github.com/containerd/containerd"},
		RecordPin:     &pin,
		Product:       product,
		Affected: &domain.AffectedResult{
			Scope:           outcomeScope(projectPrimary),
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{
			RootCauses: []domain.SymbolRef{subj},
			MandatoryConditions: []domain.Condition{{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{subj},
			}},
			UnresolvedSubjects: []domain.SymbolRef{subj},
			AbsentSubjects:     []domain.SymbolRef{subj},
		},
		RootCause: &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{{
				Package: subj.Package, Symbol: subj.Symbol, Role: domain.RootCauseSink,
				Origin: origin, Absent: true, Binding: binding,
			}},
		},
		Claims: claims,
	}
	c.EvidenceGraph.AddEvidence(inventory)
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          effective,
		Claims:         claims,
		Result:         projectAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize absent-candidate record: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

func projectAdmittedBinding() *domain.CandidateBinding {
	return &domain.CandidateBinding{
		Status: domain.CandidateBindingAdmitted, Module: "github.com/containerd/containerd",
		Version: "v1.7.27", PatchPath: "libnetwork/osl/namespace_linux.go",
	}
}

// projectSaveWithdrawnNepf overlays the pre-withdrawal saved conclusion on a
// case whose negative no longer re-admits: the stored envelope is rewritten to
// DECIDED / NO_EXPLOIT_PATH_FOUND exactly as the withdrawn Slice B persisted
// it, and the case is re-finalized. This is the historical state, not a
// recomputation — the publication gate is then asked whether that saved
// conclusion still stands.
func projectSaveWithdrawnNepf(t *testing.T, c *domain.AnalysisCase, conditionID domain.ConditionID) {
	t.Helper()
	if len(c.ProfileAssessments) == 0 {
		t.Fatal("fixture has no profile assessment")
	}
	nepf := domain.VerdictResult{
		Verdict:      domain.VerdictNoExploitPathFound,
		Reason:       "mandatory exploit condition is proven false",
		ConditionIDs: []domain.ConditionID{conditionID},
	}
	c.ProfileAssessments[0].Result = domain.AssessmentResult{
		Outcome: domain.OutcomeDecided,
		Verdict: &nepf,
	}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize the saved withdrawn conclusion: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
}

// projectVerifierFixture writes a snapshot root whose vendor tree carries the
// selected module at the recorded version, so the verifier can resolve a
// candidate's module-relative patch coordinate against that source.
func projectVerifierFixture(t *testing.T, module, version string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/prod\n\ngo 1.15\n\nrequire "+module+" "+version+"\n")
	write("prod.go", "package prod\n\nfunc Main() {}\n")
	manifest := "# " + module + " " + version + "\n## explicit\n"
	seen := map[string]bool{}
	for rel := range files {
		dir := path.Dir(rel)
		pkg := module
		if dir != "." {
			pkg += "/" + dir
		}
		if !seen[pkg] {
			seen[pkg] = true
			manifest += pkg + "\n"
		}
		write("vendor/"+module+"/"+rel, files[rel])
	}
	write("vendor/modules.txt", manifest)
	return root
}

// F1: withdrawing the content-derived proof must not let a saved conclusion
// resurrect through the coordinate bindings it left behind.
//
// The candidates are verifier-produced: each carries an ADMITTED patch-coordinate
// binding the verifier itself derived against the selected version's own source.
// That observation is not absence authority, and adding duplicate manual and
// LLM-projected candidates for the same subjects is a relabel, not a new input.
// The dependent absent subjects are pruned, the FALSE claim is demoted, and the
// saved NO_EXPLOIT_PATH_FOUND envelope does not publish. History — evidence,
// claims and the stored result — stays exactly as recorded.
func TestWithdrawnBindingCannotResurrectThroughCoordinate(t *testing.T) {
	const module = "github.com/containerd/containerd"
	const version = "v1.7.27"
	root := projectVerifierFixture(t, module, version, map[string]string{
		"libnetwork/osl/namespace_linux.go": "package osl\n\nfunc setIPv6() error { return nil }\n",
	})
	subj := domain.SymbolRef{Package: module + "/libnetwork/osl", Symbol: "setIPv6"}

	build := composeBuild()
	pin := composePin(projectPrimary)
	product := composeProduct(build)
	product.Target = &domain.ProductTarget{
		GOOS: build.GOOS, GOARCH: build.GOARCH,
		Source:          domain.ProductTargetSourceArtifactBuildInfo,
		Scope:           domain.ProductTargetScopeArtifact,
		ArtifactSHA256:  strings.Repeat("a", 64),
		BuildInfoSHA256: strings.Repeat("b", 64),
	}
	effective := domain.EffectiveBuildContext(product)
	c := &domain.AnalysisCase{
		ID:            projectPrimaryCase,
		RequestedID:   projectPrimary,
		Vulnerability: domain.Vulnerability{ID: projectPrimary, Scope: outcomeScope(projectPrimary), Module: module},
		RecordPin:     &pin,
		Product:       product,
		Affected: &domain.AffectedResult{
			Scope:           outcomeScope(projectPrimary),
			SelectedModule:  module,
			SelectedModules: []string{module},
			ResolvedVersion: version,
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID:           "EV-PKGS",
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		Tool:         "go",
		Source:       "go list -deps -test -json ./...",
		Command:      "go list -deps -test -json ./...",
		Content:      `{"ImportPath":"github.com/kubernetes/kubernetes"}`,
		BuildContext: &effective,
		PackageList:  &domain.PackageListRun{Completed: true, Complete: true, WithTests: true, Pattern: "./..."},
	})

	// A fix-derived candidate whose only identity observation is the patch
	// coordinate: the layer that could re-derive it as an admitted proof is
	// withdrawn, so the verifier records the coordinate but refuses absence.
	model := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: subj.Package, Symbol: subj.Symbol, Role: domain.RootCauseSink,
			Origin: domain.RootCauseOriginFixDerived,
			Binding: &domain.CandidateBinding{
				Status: domain.CandidateBindingUnmeasured, Module: module,
				PatchPath: "libnetwork/osl/namespace_linux.go",
			},
		}},
	}
	rootcause.Verifier{Source: &goanalysis.Index{Dir: root}}.Verify(
		context.Background(), c, model, c.Vulnerability)

	if len(model.Unverified) != 1 {
		t.Fatalf("unverified=%+v — the coordinate-only candidate must stay blocking", model.Unverified)
	}
	verified := model.Unverified[0]
	if verified.Binding == nil || verified.Binding.Status != domain.CandidateBindingAdmitted {
		t.Fatalf("binding=%+v — the verifier must record the resolved coordinate", verified.Binding)
	}
	if verified.Absent {
		t.Fatalf("candidate=%+v — a coordinate binding alone grounded absence", verified)
	}

	// The pre-withdrawal saved state: the verifier-produced candidate was in
	// the resolved set, flagged absent, and its absence grounded the record's
	// negative. Restore that historical shape so the publication gate is asked
	// the real question.
	savedCandidate := verified
	savedCandidate.Absent = true
	savedCandidate.EvidenceIDs = []domain.EvidenceID{"EV-PKGS"}
	claims := []domain.Claim{{
		ID:          "CL-C-REACH",
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierPackageAbsent,
		EvidenceIDs: []domain.EvidenceID{"EV-PKGS"},
		Producer:    "evaluator.SymbolReachable",
		NegativeVerification: &domain.NegativeVerification{
			Status:       domain.NegativeVerified,
			EvidenceIDs:  []domain.EvidenceID{"EV-PKGS"},
			BuildContext: &effective,
		},
	}}
	c.RootCause = &domain.RootCauseModel{
		Status:     domain.RootCauseResolved,
		RootCauses: []domain.RootCause{savedCandidate},
		// Duplicate labels for the same subject: a manual relabel and an LLM
		// proposal. Neither is a new operator input, and neither erases the
		// refused dependency.
		Alternatives: []domain.RootCause{
			{Package: subj.Package, Symbol: subj.Symbol, Role: domain.RootCauseSink,
				Origin: domain.RootCauseOriginManual},
			{Package: subj.Package, Symbol: subj.Symbol, Role: domain.RootCauseSink,
				Origin: domain.RootCauseOriginLLMProposed},
		},
	}
	c.Exploit = &domain.ExploitModel{
		RootCauses: []domain.SymbolRef{subj},
		MandatoryConditions: []domain.Condition{{
			ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
			Subjects: []domain.SymbolRef{subj},
		}},
		UnresolvedSubjects: []domain.SymbolRef{subj},
		AbsentSubjects:     []domain.SymbolRef{subj},
	}
	c.Claims = claims
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          effective,
		Claims:         claims,
	}}
	projectSaveWithdrawnNepf(t, c, "C-REACH")
	if got := c.ProfileAssessments[0].Result.Verdict; got == nil ||
		got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("fixture did not save a NO_EXPLOIT_PATH_FOUND: %+v", c.ProfileAssessments[0].Result)
	}

	// Dependent absent subjects and the FALSE claim do not admit: the honest
	// recomputation is a root-cause failure, not a negative.
	honest := projectAssess(c, claims)
	if honest.Outcome == domain.OutcomeDecided && honest.Verdict != nil &&
		honest.Verdict.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatalf("dependent absence still admitted: %+v", honest)
	}
	if !projectHasGap(honest.Gaps, domain.GapOwnerCode, domain.GapRootCauseUnresolved) {
		t.Fatalf("gaps=%+v — want CODE/ROOT_CAUSE_UNRESOLVED", honest.Gaps)
	}

	// And the saved conclusion does not publish.
	view, err := finding.Project(c)
	if err == nil {
		t.Fatalf("projection published a withdrawn conclusion: %+v", view.Requested)
	}
	if !strings.Contains(err.Error(), "not supported by the current record assessment") &&
		!strings.Contains(err.Error(), "no longer matches current admission") {
		t.Fatalf("refusal does not name the unsupported saved conclusion: %v", err)
	}

	// History is preserved: evidence, claims and the saved result are untouched
	// by the refusal.
	if len(c.EvidenceGraph.EvidenceList()) == 0 {
		t.Fatal("historical evidence was dropped")
	}
	if len(c.Claims) == 0 {
		t.Fatal("historical claims were dropped")
	}
	if got := c.ProfileAssessments[0].Result; got.Outcome != domain.OutcomeDecided ||
		got.Verdict == nil || got.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("saved result was rewritten instead of refused: %+v", got)
	}
}

// projectHasGap reports one typed gap cause in an assessment result.
func projectHasGap(gaps []domain.AnalysisGap, owner domain.GapOwner, code domain.GapCode) bool {
	for _, g := range gaps {
		if g.Owner == owner && g.Code == code {
			return true
		}
	}
	return false
}

// Replay: a saved conclusion whose subject has no admitted absence basis must
// not re-admit at the publication boundary. The baseline case is the
// pre-withdrawal shape itself — a verifier-admitted coordinate binding and
// nothing else — and each mutation only removes an even weaker claim. The
// historical evidence and the saved result stay exactly as recorded; only the
// conclusion is refused, and no grandfathering applies.
func TestProjectRefusesAbsentCandidateNegativeWithoutAdmissibleBinding(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*domain.RootCauseModel)
	}{
		{
			name:   "admitted coordinate binding only (pre-withdrawal saved state)",
			mutate: func(*domain.RootCauseModel) {},
		},
		{
			name: "unmapped patch coordinate",
			mutate: func(m *domain.RootCauseModel) {
				m.RootCauses[0].Binding = &domain.CandidateBinding{
					Status: domain.CandidateBindingUnmapped, Module: "github.com/containerd/containerd",
					Version: "v1.7.27", PatchPath: "cmd/containerd/server/server.go",
					SourceKind: "vendor",
				}
			},
		},
		{
			name: "missing binding (legacy record)",
			mutate: func(m *domain.RootCauseModel) {
				m.RootCauses[0].Origin = ""
				m.RootCauses[0].Binding = nil
			},
		},
		{
			name: "unmeasured binding",
			mutate: func(m *domain.RootCauseModel) {
				m.RootCauses[0].Binding = &domain.CandidateBinding{
					Status: domain.CandidateBindingUnmeasured, Module: "github.com/containerd/containerd",
					PatchPath: "cmd/containerd/server/server.go",
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := projectAbsentCandidateRecord(t, projectAdmittedBinding(), domain.RootCauseOriginFixDerived)
			projectSaveWithdrawnNepf(t, c, "C-REACH")
			savedVerdict := c.ProfileAssessments[0].Result.Verdict
			if savedVerdict == nil || savedVerdict.Verdict != domain.VerdictNoExploitPathFound {
				t.Fatalf("fixture did not save a NEPF: %+v", c.ProfileAssessments[0].Result)
			}
			tc.mutate(c.RootCause)

			if _, err := finding.Project(c); err == nil {
				t.Fatal("projection admitted a saved negative whose subject has no selected-version identity")
			} else if !strings.Contains(err.Error(), "not supported by the current record assessment") &&
				!strings.Contains(err.Error(), "no longer matches current admission") {
				t.Fatalf("refusal does not name the unsupported saved conclusion: %v", err)
			}

			// History is preserved: evidence, claims and the saved result are
			// untouched by the refusal.
			if len(c.EvidenceGraph.EvidenceList()) == 0 {
				t.Fatal("historical evidence was dropped")
			}
			if len(c.Claims) == 0 {
				t.Fatal("historical claims were dropped")
			}
			if got := c.ProfileAssessments[0].Result; got.Outcome != domain.OutcomeDecided ||
				got.Verdict == nil || got.Verdict.Verdict != domain.VerdictNoExploitPathFound {
				t.Fatalf("saved result was rewritten instead of refused: %+v", got)
			}
		})
	}
}

// projectClaimPositiveRecord builds an exact-record case whose saved profile
// result is the historical EXPLOITABLE positive resting on one TRUE claim.
// The caller supplies the evidence graph, so a test can encode a retired weak
// ground or a surviving typed path.
func projectClaimPositiveRecord(t *testing.T, cond domain.Condition, claim domain.Claim,
	evidence func(*domain.AnalysisCase)) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(projectPrimary)
	claims := []domain.Claim{claim}
	scope := composeScope(projectPrimary, domain.ScopeAdvisoryEntries, domain.CoverageComplete)
	c := &domain.AnalysisCase{
		ID:            projectPrimaryCase,
		RequestedID:   projectPrimary,
		Vulnerability: domain.Vulnerability{ID: projectPrimary, Module: "mod/amqp", Scope: scope},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected: &domain.AffectedResult{
			Scope:           scope,
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{cond}},
		Claims:  claims,
	}
	evidence(c)
	// The saved result is the pre-cutover positive: projectAssess is run
	// without the case so the fixture records the historical conclusion
	// instead of today's re-admission.
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         projectAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize %q: %v", c.ID, err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// TestPersistedWeakPositiveIsNotReadmitted: a saved TRUE is not evidence. The
// publication gate re-establishes persisted positives against the case's own
// evidence, so a record saved from the retired unexported-sink + module-usage
// or frame-name/server-role route cannot publish, while an exact call path
// still re-admits and publishes.
func TestPersistedWeakPositiveIsNotReadmitted(t *testing.T) {
	unexportedSink := domain.SymbolRef{Package: "mod/amqp", Symbol: "readLongstr"}
	reachCond := domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
		Subjects: []domain.SymbolRef{unexportedSink},
	}
	reachClaim := domain.Claim{
		ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue,
		EvidenceIDs: []domain.EvidenceID{"EV-USE-SCAN"},
		Producer:    "evaluator.SymbolReachable",
	}
	moduleUsageEvidence := func(subject domain.SymbolRef) func(*domain.AnalysisCase) {
		return func(c *domain.AnalysisCase) {
			build := domain.EffectiveBuildContext(c.Product)
			c.EvidenceGraph.AddEvidence(domain.Evidence{
				ID: "EV-USE-SCAN", Kind: domain.EvidenceSourceScan,
				Quality:      domain.QualityDeterministic,
				Source:       "source index: module usage measurement",
				Tool:         "goanalysis.Index.ModuleUsage",
				BuildContext: &build,
				SourceScan: &domain.SourceScanRun{
					Module: "mod/amqp", Subjects: []domain.SymbolRef{subject},
					Completed: true, Complete: true,
				},
			})
			c.EvidenceGraph.AddModuleUsages(domain.CallSite{
				Package: "prod/amqp", Function: "DialTLS",
				Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
			})
		}
	}

	t.Run("saved unexported-sink module-usage positive is refused", func(t *testing.T) {
		c := projectClaimPositiveRecord(t, reachCond, reachClaim, moduleUsageEvidence(unexportedSink))
		if got := c.ProfileAssessments[0].Result.Verdict; got == nil || got.Verdict != domain.VerdictExploitable {
			t.Fatalf("fixture did not save the historical positive: %+v", c.ProfileAssessments[0].Result)
		}
		view, err := finding.Project(c)
		if err == nil {
			t.Fatalf("projection published a saved unexported-sink module-usage positive: %+v", view.Requested)
		}
		if !strings.Contains(err.Error(), "not supported by the current record assessment") {
			t.Fatalf("refusal does not name the unsupported saved conclusion: %v", err)
		}
		// History is preserved: the saved claim and result stay as recorded.
		if got := c.Claims[0].Result; got != domain.ClaimTrue {
			t.Fatalf("saved claim was rewritten instead of refused: %s", got)
		}
		if got := c.ProfileAssessments[0].Result; got.Outcome != domain.OutcomeDecided ||
			got.Verdict == nil || got.Verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("saved result was rewritten instead of refused: %+v", got)
		}
	})

	t.Run("saved frame-name transport positive is refused", func(t *testing.T) {
		cond := domain.Condition{
			ID: "C-ATTACK", Kind: domain.ConditionAttackerControl, Mandatory: true,
		}
		claim := domain.Claim{
			ID: "CL-C-ATTACK", ConditionID: "C-ATTACK", Result: domain.ClaimTrue,
			EvidenceIDs: []domain.EvidenceID{"EV-CALLPATH"},
			Producer:    "evaluator.ServerTransportInput",
		}
		c := projectClaimPositiveRecord(t, cond, claim, func(c *domain.AnalysisCase) {
			c.EvidenceGraph.AddEvidence(domain.Evidence{
				ID: "EV-CALLPATH", Kind: domain.EvidenceCallPath,
				Quality: domain.QualityDeterministic, Content: "server transport frame",
			})
			c.EvidenceGraph.AddCallPath(domain.CallPath{
				EvidenceID: "EV-CALLPATH",
				Frames: []domain.CallSite{{
					Package: "mod/amqp", Receiver: "*http2Server", Function: "HandleStreams",
				}},
			})
		})
		if got := c.ProfileAssessments[0].Result.Verdict; got == nil || got.Verdict != domain.VerdictExploitable {
			t.Fatalf("fixture did not save the historical positive: %+v", c.ProfileAssessments[0].Result)
		}
		view, err := finding.Project(c)
		if err == nil {
			t.Fatalf("projection published a saved frame-name positive: %+v", view.Requested)
		}
		if !strings.Contains(err.Error(), "not supported by the current record assessment") {
			t.Fatalf("refusal does not name the unsupported saved conclusion: %v", err)
		}
	})

	t.Run("saved direct-call positive still publishes", func(t *testing.T) {
		subject := domain.SymbolRef{Package: "mod/amqp", Symbol: "Parse"}
		cond := domain.Condition{
			ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
			Subjects: []domain.SymbolRef{subject},
		}
		claim := domain.Claim{
			ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue,
			EvidenceIDs: []domain.EvidenceID{"EV-USE-SCAN"},
			Producer:    "evaluator.SymbolReachable",
		}
		c := projectClaimPositiveRecord(t, cond, claim, func(c *domain.AnalysisCase) {
			build := domain.EffectiveBuildContext(c.Product)
			c.EvidenceGraph.AddEvidence(domain.Evidence{
				ID: "EV-USE-SCAN", Kind: domain.EvidenceSourceScan,
				Quality:      domain.QualityDeterministic,
				Source:       "source index: module usage measurement",
				Tool:         "goanalysis.Index.ModuleUsage",
				BuildContext: &build,
				SourceScan: &domain.SourceScanRun{
					Module: "mod/amqp", Subjects: []domain.SymbolRef{subject},
					Completed: true, Complete: true,
				},
			})
			c.EvidenceGraph.AddModuleUsages(domain.CallSite{
				Package: "prod/amqp", Function: "main",
				Callee: "mod/amqp.Parse", ModuleOwner: "mod/amqp",
			})
		})
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("projection refused a re-established direct-call positive: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeDecided ||
			view.Requested.Verdict != domain.VerdictExploitable {
			t.Fatalf("requested = %s/%q", view.Requested.Outcome, view.Requested.Verdict)
		}
		if len(view.Witnesses) != 1 {
			t.Fatalf("witnesses = %+v", view.Witnesses)
		}
	})
}

func TestPublicationReadmitsInsteadOfReusingRunAdmission(t *testing.T) {
	c := projectPositiveRecord(t, projectPrimaryCase, projectPrimary)
	view, err := finding.Project(c)
	if err != nil {
		t.Fatalf("project initial case: %v", err)
	}
	if view.Requested.Outcome != domain.OutcomeDecided {
		t.Fatalf("outcome = %s, want DECIDED", view.Requested.Outcome)
	}

	// Invalidate the underlying evidence in the case so that fresh re-admission at publication boundary fails.
	// If publication erroneously reused run-time admission tokens/values, this tampering would not be caught.
	c.EvidenceGraph = domain.EvidenceGraph{}
	_, err = finding.Project(c)
	if err == nil {
		t.Fatal("publication unexpectedly succeeded without freshly re-admitting against current evidence")
	}
}

func TestForgedCompleteConfigPublicationRefuses(t *testing.T) {
	for _,falsifier:=range []string{domain.FalsifierSafeConfigAssignment,domain.FalsifierZeroValueConfig,domain.FalsifierSafeConfigKey} {
		c:=axesNEPFCase(t,projectPrimaryCase,projectPrimary,axesAffirmative(projectPrimary))
		for i:=range c.Claims {c.Claims[i].Falsifier=falsifier}
		for i:=range c.ProfileAssessments {for j:=range c.ProfileAssessments[i].Claims {c.ProfileAssessments[i].Claims[j].Falsifier=falsifier}}
		if _,err:=finding.Project(c);err==nil {t.Fatalf("%s forged current publication admitted",falsifier)}
		if c.Claims[0].NegativeVerification.Status!=domain.NegativeVerified {t.Fatal("publication destroyed historical verification")}
	}
}

package finding_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/finding"
)

// axesAffirmative is the four-fact applicability chain. The optional
// implementation-presence axis is deliberately left UNKNOWN.
func axesAffirmative(recordID string) *domain.AffectedResult {
	return &domain.AffectedResult{
		Scope:           outcomeScope(recordID),
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}
}

func axesNEPFClaims() (domain.ExploitModel, []domain.Claim) {
	claims := []domain.Claim{{
		ID:          "CL-CFG",
		ConditionID: "C-CFG",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierSnapshotFactMismatch,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID: "C-CFG", Kind: domain.ConditionRuntime, Mandatory: true,
	}}}
	return model, claims
}

// axesNEPFCase builds a genuine exact-request NEPF record: the evaluator earns
// the verdict from a verified mandatory-condition falsifier, not from a
// hand-written assessment result.
func axesNEPFCase(t *testing.T, id domain.CaseID, recordID string,
	affected *domain.AffectedResult) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(recordID)
	model, claims := axesNEPFClaims()
	c := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   recordID,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: outcomeScope(recordID)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected:      affected,
		Exploit:       &model,
		Claims:        claims,
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         projectAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize NEPF case %q: %v", id, err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// axesNegativeCase builds a genuine earned NOT_AFFECTED record for one
// affected-chain absence route.
func axesNegativeCase(t *testing.T, id domain.CaseID, recordID string,
	affected *domain.AffectedResult) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(recordID)
	c := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   recordID,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: outcomeScope(recordID)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected:      affected,
	}
	// Package-presence, build-relevance and implementation-presence negatives
	// are build-dependent: admission requires a recorded product target, and
	// package absence additionally requires a completed inventory.
	c.Product.Target = &domain.ProductTarget{
		GOOS: build.GOOS, GOARCH: build.GOARCH, CGOEnabled: build.CGOEnabled,
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID:           "EV-PACKAGES",
		Kind:         domain.EvidencePackageList,
		Quality:      domain.QualityDeterministic,
		Source:       "axes-test",
		Content:      `{"ImportPath":"example.com/product"}`,
		PackageList:  &domain.PackageListRun{Completed: true, Complete: true, Pattern: "./..."},
		BuildContext: &build,
	})
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         projectAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize negative case %q: %v", id, err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// axesUnadmittedNegativeCase builds a record whose affected chain carries a
// FALSE axis the evaluator refuses (no recorded product target or inventory).
// The saved result is produced by the same admission, so it is a genuine
// failed assessment with a refused negative.
func axesUnadmittedNegativeCase(t *testing.T, id domain.CaseID, recordID string,
	affected *domain.AffectedResult) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(recordID)
	c := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   recordID,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: outcomeScope(recordID)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected:      affected,
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         projectAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize unadmitted negative %q: %v", id, err)
	}
	c.Workflow.State = domain.StateFailed
	return c
}

// axesFailedCase builds a failed exact-request assessment whose applicability
// facts are independently established.
func axesFailedCase(t *testing.T, id domain.CaseID, recordID string,
	affected *domain.AffectedResult) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(recordID)
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID: "C-RUN", Kind: domain.ConditionSymbolReachable, Mandatory: true,
	}}}
	c := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   recordID,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: outcomeScope(recordID)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected:      affected,
		Exploit:       &model,
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Result:         projectAssess(c, nil),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize failed case %q: %v", id, err)
	}
	c.Workflow.State = domain.StateFailed
	return c
}

// axesExternalCase builds an external-dependency assessment whose applicability
// facts are independently established.
func axesExternalCase(t *testing.T, id domain.CaseID, recordID string,
	affected *domain.AffectedResult) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(recordID)
	dependency := domain.ExternalDependency{
		MissingFact:             "the deployment's input path to the vulnerable parser",
		AffectedObligation:      domain.ObligationCondition,
		BoundaryEvidenceRefs:    []domain.QualifiedRef{{AssessmentID: id, Ref: "EV-EXT"}},
		WhyArtifactCannotSupply: "the input path is a property of the deployment, not of the artifact",
		AlternativesChanging:    []string{"the parser is reachable", "the parser is not reachable"},
		ResolvingEvidence:       "the deployment ingress configuration",
	}
	claims := []domain.Claim{{
		ID:          "CL-EXT",
		ConditionID: "C-EXT",
		Result:      domain.ClaimUnknown,
		AnalysisGaps: []domain.AnalysisGap{{
			Owner:        domain.GapOwnerExternal,
			Code:         domain.GapExternalDependencyUnresolved,
			Obligation:   domain.ObligationCondition,
			AssessmentID: id,
			Message:      "the deployment does not record the input path",
			External:     &dependency,
		}},
	}}
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID: "C-EXT", Kind: domain.ConditionInputConstraint, Mandatory: true,
	}}}
	c := &domain.AnalysisCase{
		ID:            id,
		RequestedID:   recordID,
		Vulnerability: domain.Vulnerability{ID: recordID, Scope: outcomeScope(recordID)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected:      affected,
		Exploit:       &model,
		Claims:        claims,
	}
	projectAddEvidence(c, "EV-EXT")
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         projectAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize external case %q: %v", id, err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

// axesCVEWithNEPFPrimary builds a CVE request whose primary record earned NEPF
// with affirmative applicability facts. The request itself has no positive and
// no corpus, so it stays unresolved.
func axesCVEWithNEPFPrimary(t *testing.T) *domain.AnalysisCase {
	t.Helper()
	build := composeBuild()
	pin := composePin(projectPrimary)
	model, claims := axesNEPFClaims()
	c := &domain.AnalysisCase{
		ID:            projectPrimaryCase,
		RequestedID:   projectCVE,
		Vulnerability: domain.Vulnerability{ID: projectPrimary, Scope: composeScope(projectCVE, domain.ScopeCVE, domain.CoverageKnownOnly)},
		RecordPin:     &pin,
		Product:       composeProduct(build),
		Affected:      axesAffirmative(projectPrimary),
		Exploit:       &model,
		Claims:        claims,
	}
	c.ProfileAssessments = []domain.ProfileAssessment{{
		Profile:        domain.ProfileZeroTrust,
		IsTargetActual: true,
		Build:          build,
		Claims:         claims,
		Result:         projectAssess(c, claims),
	}}
	if err := finding.Finalize(c); err != nil {
		t.Fatalf("finalize CVE with NEPF primary: %v", err)
	}
	c.Workflow.State = domain.StateCompleted
	return c
}

func axesRequestedRow(t *testing.T, view finding.View) finding.AxisRow {
	t.Helper()
	row, ok := view.Axes.TargetRequested()
	if !ok {
		t.Fatal("projection carries no target-actual requested row")
	}
	return row
}

func axesRecordRow(t *testing.T, view finding.View, id domain.CaseID) finding.AxisRow {
	t.Helper()
	row, ok := view.Axes.TargetRecord(id)
	if !ok {
		t.Fatalf("projection carries no target-actual row for assessment %q", id)
	}
	return row
}

func TestAssessmentAxesProjection(t *testing.T) {
	t.Run("affirmative applicability with optional implementation UNKNOWN", func(t *testing.T) {
		c := axesNEPFCase(t, projectPrimaryCase, projectPrimary, axesAffirmative(projectPrimary))
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		requested := axesRequestedRow(t, view)
		if requested.VulnerableCodeInBuild != finding.AxisTrue || requested.Exploitable != finding.AxisFalse {
			t.Fatalf("requested axes = %s/%s", requested.VulnerableCodeInBuild, requested.Exploitable)
		}
		record := axesRecordRow(t, view, projectPrimaryCase)
		if record.VulnerableCodeInBuild != finding.AxisTrue || record.Exploitable != finding.AxisFalse {
			t.Fatalf("record axes = %s/%s", record.VulnerableCodeInBuild, record.Exploitable)
		}
		if record.Record == nil || record.Record.RecordID != projectPrimary {
			t.Fatalf("record row carries no exact pin: %+v", record.Record)
		}
		if requested.Record != nil {
			t.Fatalf("requested row acquired a record pin: %+v", requested.Record)
		}
	})

	t.Run("each admitted absence route is FALSE", func(t *testing.T) {
		routes := map[string]func(*domain.AffectedResult){
			"module absent":      func(a *domain.AffectedResult) { a.ModulePresent = domain.ClaimFalse },
			"version unaffected": func(a *domain.AffectedResult) { a.VersionAffected = domain.ClaimFalse },
			"package absent":     func(a *domain.AffectedResult) { a.PackagePresent = domain.ClaimFalse },
			"build irrelevant":   func(a *domain.AffectedResult) { a.BuildRelevant = domain.ClaimFalse },
			"implementation absent": func(a *domain.AffectedResult) {
				a.VulnerableImplementationPresent = domain.ClaimFalse
			},
		}
		for name, mutate := range routes {
			t.Run(name, func(t *testing.T) {
				affected := axesAffirmative(projectPrimary)
				mutate(affected)
				c := axesNegativeCase(t, projectPrimaryCase, projectPrimary, affected)
				view, err := finding.Project(c)
				if err != nil {
					t.Fatalf("project: %v", err)
				}
				requested := axesRequestedRow(t, view)
				if requested.VulnerableCodeInBuild != finding.AxisFalse {
					t.Fatalf("requested vulnerability = %s, want FALSE", requested.VulnerableCodeInBuild)
				}
				if requested.Exploitable != finding.AxisNotApplicable {
					t.Fatalf("requested exploitability = %s, want NOT_APPLICABLE (outcome=%s verdict=%s reason=%s)",
						requested.Exploitable, view.Requested.Outcome, view.Requested.Verdict, view.Requested.Reason)
				}
				record := axesRecordRow(t, view, projectPrimaryCase)
				if record.VulnerableCodeInBuild != finding.AxisFalse || record.Exploitable != finding.AxisNotApplicable {
					t.Fatalf("record axes = %s/%s", record.VulnerableCodeInBuild, record.Exploitable)
				}
			})
		}
	})

	t.Run("a refused affected negative never becomes FALSE", func(t *testing.T) {
		affected := axesAffirmative(projectPrimary)
		affected.PackagePresent = domain.ClaimFalse
		c := axesUnadmittedNegativeCase(t, projectPrimaryCase, projectPrimary, affected)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeFailed {
			t.Fatalf("requested outcome = %s, want FAILED", view.Requested.Outcome)
		}
		requested := axesRequestedRow(t, view)
		if requested.VulnerableCodeInBuild != finding.AxisUnknown {
			t.Fatalf("refused negative became %s, want UNKNOWN", requested.VulnerableCodeInBuild)
		}
		if requested.Exploitable != finding.AxisUnknown {
			t.Fatalf("refused negative exploitability = %s, want UNKNOWN", requested.Exploitable)
		}
		record := axesRecordRow(t, view, projectPrimaryCase)
		if record.VulnerableCodeInBuild != finding.AxisUnknown {
			t.Fatalf("record refused negative became %s, want UNKNOWN", record.VulnerableCodeInBuild)
		}
	})

	t.Run("NEPF with unknown applicability is UNKNOWN/FALSE", func(t *testing.T) {
		affected := &domain.AffectedResult{Scope: outcomeScope(projectPrimary)}
		c := axesNEPFCase(t, projectPrimaryCase, projectPrimary, affected)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		requested := axesRequestedRow(t, view)
		if requested.VulnerableCodeInBuild != finding.AxisUnknown || requested.Exploitable != finding.AxisFalse {
			t.Fatalf("requested axes = %s/%s, want UNKNOWN/FALSE",
				requested.VulnerableCodeInBuild, requested.Exploitable)
		}
	})

	t.Run("failed analysis retains affirmative applicability", func(t *testing.T) {
		c := axesFailedCase(t, projectPrimaryCase, projectPrimary, axesAffirmative(projectPrimary))
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeFailed {
			t.Fatalf("requested outcome = %s", view.Requested.Outcome)
		}
		requested := axesRequestedRow(t, view)
		if requested.VulnerableCodeInBuild != finding.AxisTrue || requested.Exploitable != finding.AxisUnknown {
			t.Fatalf("requested axes = %s/%s, want TRUE/UNKNOWN",
				requested.VulnerableCodeInBuild, requested.Exploitable)
		}
	})

	t.Run("external dependency retains affirmative applicability", func(t *testing.T) {
		c := axesExternalCase(t, projectPrimaryCase, projectPrimary, axesAffirmative(projectPrimary))
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeExternal {
			t.Fatalf("requested outcome = %s", view.Requested.Outcome)
		}
		requested := axesRequestedRow(t, view)
		if requested.VulnerableCodeInBuild != finding.AxisTrue || requested.Exploitable != finding.AxisUnknown {
			t.Fatalf("requested axes = %s/%s, want TRUE/UNKNOWN",
				requested.VulnerableCodeInBuild, requested.Exploitable)
		}
		if !view.Requested.IsTargetActual {
			t.Fatal("requested row is not the actual profile")
		}
	})

	t.Run("scoped positive keeps its boundary", func(t *testing.T) {
		c := projectPositiveRecord(t, projectPrimaryCase, projectPrimary)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		requested := axesRequestedRow(t, view)
		if requested.VulnerableCodeInBuild != finding.AxisTrue || requested.Exploitable != finding.AxisTrue {
			t.Fatalf("requested axes = %s/%s, want TRUE/TRUE",
				requested.VulnerableCodeInBuild, requested.Exploitable)
		}
		if requested.ExploitabilityScope != domain.ScopeLibraryAPI {
			t.Fatalf("exploitability scope = %q, want %q", requested.ExploitabilityScope, domain.ScopeLibraryAPI)
		}
		record := axesRecordRow(t, view, projectPrimaryCase)
		if record.ExploitabilityScope != domain.ScopeLibraryAPI {
			t.Fatalf("record exploitability scope = %q", record.ExploitabilityScope)
		}
	})

	t.Run("a record NEPF does not lift to a CVE answer", func(t *testing.T) {
		c := axesCVEWithNEPFPrimary(t)
		view, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		if view.Requested.Outcome != domain.OutcomeFailed ||
			view.Requested.Coverage != domain.CoverageKnownOnly {
			t.Fatalf("requested = %s/%s", view.Requested.Outcome, view.Requested.Coverage)
		}
		requested := axesRequestedRow(t, view)
		if requested.SubjectID != projectCVE {
			t.Fatalf("requested subject = %q", requested.SubjectID)
		}
		if requested.VulnerableCodeInBuild != finding.AxisUnknown || requested.Exploitable != finding.AxisUnknown {
			t.Fatalf("requested axes = %s/%s, want UNKNOWN/UNKNOWN",
				requested.VulnerableCodeInBuild, requested.Exploitable)
		}
		record := axesRecordRow(t, view, projectPrimaryCase)
		if record.VulnerableCodeInBuild != finding.AxisTrue || record.Exploitable != finding.AxisFalse {
			t.Fatalf("record axes = %s/%s, want the record's own TRUE/FALSE",
				record.VulnerableCodeInBuild, record.Exploitable)
		}
		if record.SubjectID != projectPrimary {
			t.Fatalf("record subject = %q, want %q", record.SubjectID, projectPrimary)
		}
	})
}

func TestAssessmentAxesCompatibility(t *testing.T) {
	t.Run("an existing analysis-case/2 re-admits with identical axes", func(t *testing.T) {
		c := projectCVEPositive(t)
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal case: %v", err)
		}
		if bytes.Contains(raw, []byte("assessment_axes")) {
			t.Fatal("the persisted case acquired a display projection")
		}
		var clone domain.AnalysisCase
		if err := json.Unmarshal(raw, &clone); err != nil {
			t.Fatalf("unmarshal case: %v", err)
		}
		first, err := finding.Project(c)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		second, err := finding.Project(&clone)
		if err != nil {
			t.Fatalf("project cloned case: %v", err)
		}
		if !reflect.DeepEqual(first.Requested, second.Requested) {
			t.Fatal("re-admission changed the requested finding")
		}
		if !reflect.DeepEqual(first.Axes, second.Axes) {
			t.Fatalf("re-admission changed the axes:\nfirst=%+v\nsecond=%+v", first.Axes, second.Axes)
		}
		if len(first.Axes.Records) != 2 {
			t.Fatalf("record axes = %d, want the primary and the witness", len(first.Axes.Records))
		}
	})

	t.Run("the projection does not mutate the saved case", func(t *testing.T) {
		c := axesCVEWithNEPFPrimary(t)
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
		if !bytes.Equal(before, after) {
			t.Fatal("Project mutated the persisted case")
		}
	})
}

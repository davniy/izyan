package triage

// Replay catalog-gate tests: the port review requires that a missing,
// stale or foreign condition catalog fails replay closed — the
// recomputed falsifier report then differs from a persisted verified
// report, and the decision-hash comparison surfaces the mismatch instead
// of trusting the persisted proofs. These fixtures pin the shared
// GateFalsifierProposals partition, the catalog-binding.v1 round trip
// the live path now persists, and the replay-side re-enforcement.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/llm"
	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// catalogTestProposal is the falsifier proposal every fixture in this
// file scripts into the agent assessment.
var catalogTestProposal = FalsifierProposal{
	ID: "fp-1", ClaimID: "c1", ConditionID: "cond-1", Kind: FalsifierCodeAbsent,
	Subjects:     []FalsifierSubject{{Package: "example.com/dep", Symbol: "Fn"}},
	EvidenceRefs: []string{"e1"},
}

// catalogProposalReport is the persisted verified report a confused
// replay must not trust: it claims fp-1 verified, as a live run with a
// bound catalog would have produced.
func catalogProposalReport(snapshotHash string) FalsifierReport {
	proof := FalsifierProof{
		ID: catalogTestProposal.ID, ProposalID: catalogTestProposal.ID, ClaimID: "c1",
		ConditionID: "cond-1", Kind: FalsifierCodeAbsent, Status: FalsifierVerified,
		Basis: BasisCheckerVerified, Mandatory: true,
		RuleID: "advisory-code-absence", RuleVersion: "1", EvidenceRefs: []string{"e1"},
		Coverage: FalsifierCoverage{
			Scope: "snapshot", Completeness: "COMPLETE", SnapshotHash: snapshotHash,
			BuildContextHash: "build-1", ClosureHash: "closure-hash-1", ClosureComplete: true,
			CoverageRuleVersion: "4", ScopeRule: evidencetools.CodeAbsenceScopeRule,
			ScopeComplete: true, ScopeHash: "scope-hash-1", ShippingRoots: []string{"cmd/app"},
			PackageStates:            map[string]string{"cmd/app": "LIVE"},
			DynamicRelevanceRule:     evidencetools.CodeAbsenceDynamicRule,
			DynamicRelevanceComplete: true,
			ExpectedSubjects:         catalogTestProposal.Subjects,
			CheckedSubjects:          catalogTestProposal.Subjects,
			AbsentSubjects:           catalogTestProposal.Subjects,
		},
		Reason:  "deterministic checker result",
		History: []FalsifierTransition{{From: FalsifierUnknown, To: FalsifierVerified, Reason: "deterministic checker result", RuleID: "advisory-code-absence", RuleVersion: "1"}},
	}
	bindCurrentCoverageInventory(&proof.Coverage)
	return NewFalsifierReport(strings.Repeat("07", 32), proof)
}

// fixtureAdvisoryDigest is the sha256 of the advisory file
// recordProposalRun freezes — the value s0.Advisory.SHA256 records and
// the run binding's advisory_digest.
func fixtureAdvisoryDigest(t *testing.T) string {
	t.Helper()
	return sha256Hex(t, []byte(`{"id":"CVE-2025-1234","summary":"example advisory"}`))
}

// runCatalog is a signed catalog that admits the fixture proposal:
// cond-1 mandatory, code_absent allowed, bound to the fixture's
// advisory/case identity.
func runCatalog(t *testing.T, advisoryDigest, caseID string) *ConditionCatalog {
	t.Helper()
	c := &ConditionCatalog{
		SchemaVersion:   ConditionCatalogSchemaVersion,
		CatalogID:       "cat-run-1",
		AdvisoryID:      "CVE-2025-1234",
		AdvisoryDigest:  advisoryDigest,
		CaseIdentityRef: caseID,
		Conditions: []CatalogCondition{{
			ConditionID: "cond-1", Kind: "code_absence", Mandatory: true,
			CheckerID:             "advisory-code-absence",
			CheckerVersion:        "1",
			AllowedFalsifierKinds: []FalsifierKind{FalsifierCodeAbsent},
			CoverageRule:          "every mandatory subject must resolve inside the snapshot",
		}},
	}
	c.Sign()
	return c
}

// runBindingFor mirrors the live CLI's binding construction for the
// proposal-run fixture.
func runBindingFor(cat *ConditionCatalog) CatalogBinding {
	return CatalogBinding{
		AdvisoryID:          cat.AdvisoryID,
		AdvisoryDigest:      cat.AdvisoryDigest,
		CaseIdentityRef:     cat.CaseIdentityRef,
		ExpectedCatalogHash: cat.CatalogHash,
	}
}

// recordProposalRun is recordDecisionRun with the agent script carrying
// one falsifier proposal: the verified report and the catalog pair the
// caller chooses are persisted, and the decision is composed with the
// report so replay recomposition is honest. Returns the run dir.
func recordProposalRun(t *testing.T, repoDir, outDir string, clock func() time.Time, catalog *ConditionCatalog, binding CatalogBinding) string {
	t.Helper()
	ctx := context.Background()
	inputJSON, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     "scanner-123",
		Vulnerability: Vulnerability{IDs: []string{"CVE-2025-1234"}},
		Component:     Component{Name: "dep", Package: "example.com/dep", Version: "v1.0.0"},
		Target:        Target{Repository: repoDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ParseFindings(strings.NewReader(string(inputJSON)))
	if err != nil || len(findings) != 1 {
		t.Fatalf("ParseFindings: %v", err)
	}
	in := findings[0]
	manifest, err := LocalSnapshotBuilder{Now: replayClockA}.Build(ctx, in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	manifest.Materialization = MaterializationMetadata{
		Mode:           MaterializationLocal,
		SourceID:       "service-example",
		RootHash:       manifest.ContentHash,
		ResolvedCommit: manifest.ResolvedRevision,
		CreatedAt:      "2026-10-16T00:00:00Z",
	}
	s0 := goodStage0()
	s0.Input = in
	s0.Snapshot = manifest
	s0.Source = MaterializedSource{Root: repoDir, Metadata: manifest.Materialization, Cleanup: func() error { return nil }}
	s0.Proposal.VulnerabilityIDs = []string{"CVE-2025-1234"}
	s0.Advisory.ID, s0.Advisory.ResolvedID = "CVE-2025-1234", "CVE-2025-1234"
	advisoryPath := filepath.Join(t.TempDir(), "CVE-2025-1234.json")
	writeFile(t, advisoryPath, `{"id":"CVE-2025-1234","summary":"example advisory"}`)
	s0.Advisory.Path = advisoryPath
	s0.Advisory.SHA256 = sha256Hex(t, mustRead(t, advisoryPath))
	s0.Advisory.Size = int64(len(mustRead(t, advisoryPath)))
	s0.Advisory.FrozenAt = "2026-10-16T00:00:00Z"
	if s0.Resolution != nil {
		s0.Resolution.Vulnerability.ID = "CVE-2025-1234"
		s0.Resolution.Vulnerability.AffectedSymbols = []domain.SymbolRef{{Package: "example.com/dep", Symbol: "Fn"}}
		s0.Resolution.Projection.AffectedSymbols = []domain.SymbolRef{{Package: "example.com/dep", Symbol: "Fn"}}
		s0.Resolution.Record = s0.Advisory
	}
	for i := range s0.Validation.Fields {
		if s0.Validation.Fields[i].Field == "vulnerability_ids" {
			s0.Validation.Fields[i].Value = "CVE-2025-1234"
		}
	}
	s0.Materials.Materials = []Material{{
		ID: "mat-module-graph", Kind: MaterialModuleGraph, Source: "go list -m all",
		Scope: "build-graph", Availability: MaterialAvailable,
	}}

	w := ArtifactWriter{Clock: clock, Model: "test-model", ToolVersions: map[string]string{"izyan": "test"}}
	if _, err := w.WriteStage0Artifacts(ctx, outDir, s0); err != nil {
		t.Fatalf("WriteStage0Artifacts: %v", err)
	}
	agent := Assessment{
		SchemaVersion: AssessmentSchemaVersion,
		FindingID:     in.Finding.FindingID,
		Verdict:       VerdictNotExploitable,
		Summary:       "vulnerable code path is absent",
		Claims:        []Claim{refClaim("c1", "e1")},
		// e1 is the recorded deterministic observation the proposal cites:
		// a proposal may only bind det:<observation-id> canonical locators.
		Evidence:           []EvidenceRef{{ID: "e1", Kind: "det", Locator: "det:det-0001"}},
		ProposedAction:     closeAction("c1"),
		FalsifierProposals: []FalsifierProposal{catalogTestProposal},
	}
	agentJSON, err := json.Marshal(agent)
	if err != nil {
		t.Fatal(err)
	}
	subj, _ := json.Marshal([]FalsifierSubject{{Package: "example.com/dep", Symbol: "Fn"}})
	caArgs, _ := json.Marshal(map[string]any{"subjects": json.RawMessage(subj)})
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", ToolCalls: []llm.ToolCall{{
			ID: "call-1", Type: "function",
			Function: llm.FunctionCall{Name: "verify_code_absence", Arguments: string(caArgs)},
		}}},
		{Role: "assistant", Content: string(agentJSON)},
	}}
	agentIn := Stage0AgentFinding(in, s0.AdvisoryVulnerability())
	det := &DeterministicTools{
		Caller: &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
			return &evidencetools.Observation{
				ID:           "ev-ca",
				Tool:         name,
				Fact:         "closure-backed absence",
				Scope:        "product packages",
				Completeness: evidencetools.CompletenessComplete,
				ToolStatus:   evidencetools.StatusOK,
				Data:         map[string]any{"absent_subjects": []string{"example.com/dep.Fn"}},
				ScopeDetails: &evidencetools.ScopeDetails{
					SnapshotHash: manifest.ContentHash,
					BuildContext: &evidencetools.BuildContext{GOOS: "linux", GOARCH: "amd64", Toolchain: "go-test"},
				},
			}, nil
		}},
		Catalog:          CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog()),
		ObservationStore: NewRunObservationStore(AttemptRunID(in.Finding.FindingID, 1), 1),
	}
	tools := &ToolSet{Parts: []ToolExecutor{
		&ReadOnlyTools{Snapshot: manifest, Finding: agentIn, Advisory: s0.AdvisoryProjection()},
		det,
	}}
	run, err := AgentRunner{Client: client, Tools: tools, Materials: BuildAgentMaterials(s0.Materials), Limits: AgentLimits{MaxSteps: 4}}.Run(ctx, agentIn, manifest)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	gate := FactGate{Observations: ObservationIndex(tools.AuditEvents())}
	fv := gate.Validate(ctx, agentIn, manifest, run.Assessment)
	if fv.Status != ValidationComplete {
		t.Fatalf("fixture gate = %s, want COMPLETE (%+v)", fv.Status, fv)
	}
	assessment := run.Assessment
	assessment.FactValidation = fv.Status
	assessment.FactValidationDetail = &fv
	art, err := w.Write(ctx, outDir, in, manifest, run, assessment, s0.Events, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	report := catalogProposalReport(s0.Snapshot.ContentHash)
	if err := w.WriteFalsifierReport(ctx, art.RootDir, report); err != nil {
		t.Fatalf("WriteFalsifierReport: %v", err)
	}
	if err := w.WriteConditionCatalog(ctx, art.RootDir, catalog, binding); err != nil {
		t.Fatalf("WriteConditionCatalog: %v", err)
	}
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	pkg, err := Composer{
		RulesetHash: strings.Repeat("07", 32),
		Limits:      BudgetConfig{MaxLLMSteps: 32, MaxToolCalls: 128, MaxSourceBytes: 1 << 20, TimeoutSeconds: 900},
	}.ComposeWithEvidence(ctx, s0, stored, *stored.FactValidationDetail, EvidenceInput{Falsifiers: &report})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := w.WriteDecision(ctx, outDir, pkg); err != nil {
		t.Fatalf("WriteDecision: %v", err)
	}
	return art.RootDir
}

// TestReplayMissingCatalogFailsClosed: a run that persisted a verified
// falsifier report but no condition catalog replays closed — the absent
// catalog is non-admitting, the recomputed report carries a non-admitted
// proof, and the drift comparison fails instead of trusting VERIFIED.
func TestReplayMissingCatalogFailsClosed(t *testing.T) {
	runDir := recordProposalRun(t, newReplayRepo(t), t.TempDir(), replayClockA, nil, CatalogBinding{})
	if _, err := os.Stat(filepath.Join(runDir, "condition-catalog.json")); !os.IsNotExist(err) {
		t.Fatal("fixture must not persist a catalog")
	}
	if _, err := os.Stat(filepath.Join(runDir, "catalog-binding.json")); err != nil {
		t.Fatal("the binding document must always persist")
	}
	_, err := PrepareReplay(context.Background(), runDir)
	if err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("missing catalog must fail replay closed (drift), got: %v", err)
	}
}

// TestReplayForeignCatalogFailsClosed: a catalog bound to another
// advisory is foreign — the persisted binding rejects it, the proposal
// replays non-admitted, and the drift comparison fails closed.
func TestReplayForeignCatalogFailsClosed(t *testing.T) {
	outDir := t.TempDir()
	honest := runCatalog(t, fixtureAdvisoryDigest(t), "scanner-123")
	runDir := recordProposalRun(t, newReplayRepo(t), outDir, replayClockA, honest, runBindingFor(honest))

	// Swap the persisted catalog for a foreign twin — the binding
	// document stays bound to the run's advisory/case, so admission must
	// reject the foreign one.
	foreign := &ConditionCatalog{
		SchemaVersion:   ConditionCatalogSchemaVersion,
		CatalogID:       "cat-foreign",
		AdvisoryID:      "CVE-OTHER-9999",
		AdvisoryDigest:  "sha256:foreign-advisory",
		CaseIdentityRef: "other-case",
		Conditions: []CatalogCondition{{
			ConditionID: "cond-1", Kind: "code_absence", Mandatory: true,
			CheckerID:             "foreign-checker",
			CheckerVersion:        "1",
			AllowedFalsifierKinds: []FalsifierKind{FalsifierCodeAbsent},
			CoverageRule:          "foreign coverage",
		}},
	}
	foreign.Sign()
	raw, err := json.MarshalIndent(foreign, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "condition-catalog.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = PrepareReplay(context.Background(), runDir)
	if err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("foreign catalog must fail replay closed (drift), got: %v", err)
	}
}

// TestReplayTamperedCatalogFailsClosed: a catalog whose content no longer
// matches its pinned hash is stale/tampered — admission rejects every
// proposal, replay drifts, fail closed.
func TestReplayTamperedCatalogFailsClosed(t *testing.T) {
	cat := runCatalog(t, fixtureAdvisoryDigest(t), "scanner-123")
	runDir := recordProposalRun(t, newReplayRepo(t), t.TempDir(), replayClockA, cat, runBindingFor(cat))

	// Tamper: flip a condition kind after signing — the recorded hash no
	// longer matches the content.
	var stored ConditionCatalog
	if err := json.Unmarshal(mustRead(t, filepath.Join(runDir, "condition-catalog.json")), &stored); err != nil {
		t.Fatal(err)
	}
	stored.Conditions[0].Kind = "tampered_kind"
	raw, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "condition-catalog.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = PrepareReplay(context.Background(), runDir)
	if err == nil || !(strings.Contains(err.Error(), "condition catalog") || strings.Contains(err.Error(), "decision drift")) {
		t.Fatalf("tampered catalog must fail replay closed, got: %v", err)
	}
}

// TestGateFalsifierProposalsParity: the shared gate's partition is the
// single source of truth for live and replay — an admittable proposal
// lands in Admitted, a disallowed one lands in Rejected with the
// recorded non-admitted proof, and a binding-level failure rejects every
// proposal with the binding reason.
func TestGateFalsifierProposalsParity(t *testing.T) {
	c := validCatalog(t)
	bind := fullBinding(c)
	p := FalsifierProposal{ID: "fp-1", ClaimID: "c1", ConditionID: "cond-signal", Kind: FalsifierCodeAbsent}
	adm := GateFalsifierProposals(c, bind, []FalsifierProposal{p})
	if len(adm.Admitted) != 1 || len(adm.Rejected) != 0 {
		t.Fatalf("admittable proposal must admit: %+v", adm)
	}

	// Kind disallowed by the owning condition.
	bad := FalsifierProposal{ID: "fp-2", ClaimID: "c1", ConditionID: "cond-guard", Kind: FalsifierCodeAbsent}
	adm = GateFalsifierProposals(c, bind, []FalsifierProposal{bad})
	if len(adm.Admitted) != 0 || len(adm.Rejected) != 1 {
		t.Fatalf("disallowed kind must reject: %+v", adm)
	}
	if adm.Rejected[0].Status != FalsifierUnknown || adm.Rejected[0].Basis != BasisUnsupported ||
		!strings.HasPrefix(adm.Rejected[0].Reason, "falsifier proposal not admitted: ") {
		t.Fatalf("rejected proof lost the recorded refusal: %+v", adm.Rejected[0])
	}
	if len(adm.Rejected[0].History) != 1 || adm.Rejected[0].History[0].Reason != adm.Rejected[0].Reason {
		t.Fatalf("rejected proof must carry its transition: %+v", adm.Rejected[0])
	}

	// Binding-level failure rejects everything with the binding reason.
	empty := GateFalsifierProposals(c, CatalogBinding{}, []FalsifierProposal{p, bad})
	if len(empty.Admitted) != 0 || len(empty.Rejected) != 2 {
		t.Fatalf("incomplete binding must reject every proposal: %+v", empty)
	}
	if !strings.Contains(empty.Rejected[0].Reason, "catalog binding is incomplete") {
		t.Fatalf("binding rejection must name the reason: %q", empty.Rejected[0].Reason)
	}

	// A missing catalog rejects every proposal with the no-catalog reason.
	none := GateFalsifierProposals(nil, bind, []FalsifierProposal{p})
	if len(none.Admitted) != 0 || len(none.Rejected) != 1 ||
		!strings.Contains(none.Rejected[0].Reason, "no condition catalog is bound") {
		t.Fatalf("absent catalog must reject closed: %+v", none.Rejected)
	}
}

// TestCatalogBindingDocumentRoundTrip: the persisted binding decodes back
// to the identical run binding — a field dropped or renamed between live
// persist and replay load is a silent gate removal.
func TestCatalogBindingDocumentRoundTrip(t *testing.T) {
	bind := CatalogBinding{
		AdvisoryID:          "CVE-2099-0001",
		AdvisoryDigest:      "sha256:advisory-aaaa",
		CaseIdentityRef:     "case-77",
		ExpectedCatalogHash: strings.Repeat("ab", 32),
	}
	doc := bind.Document(true)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var got CatalogBindingDocument
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != CatalogBindingSchemaVersion || got.Binding() != bind || !got.CatalogPresent {
		t.Fatalf("binding round trip drifted: %+v -> %+v", bind, got)
	}
	if doc2 := bind.Document(false); doc2.CatalogPresent {
		t.Fatal("absent catalog must persist catalog_present=false")
	}
}

// recordTwoAttemptProposalRun records a run whose decision composes from
// stability retry 2: attempt 1's response proposes nothing (its tool call
// sees a denied tool — no VERIFIED basis), retry 1 records the
// closure-backed absence observation and the accepted assessment.
// Everything is written the way runTriageFinding persists it: raw-agent
// stability_runs, merged observation archive, stability.json with the
// selected_attempt pin, catalog pair, verified report, decision. Returns
// the run dir plus the attempt-2 assessment JSON for assertions.
func recordTwoAttemptProposalRun(t *testing.T, repoDir, outDir string, clock func() time.Time) string {
	t.Helper()
	ctx := context.Background()
	inputJSON, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     "scanner-123",
		Vulnerability: Vulnerability{IDs: []string{"CVE-2025-1234"}},
		Component:     Component{Name: "dep", Package: "example.com/dep", Version: "v1.0.0"},
		Target:        Target{Repository: repoDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ParseFindings(strings.NewReader(string(inputJSON)))
	if err != nil || len(findings) != 1 {
		t.Fatalf("ParseFindings: %v", err)
	}
	in := findings[0]
	manifest, err := LocalSnapshotBuilder{Now: replayClockA}.Build(ctx, in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	manifest.Materialization = MaterializationMetadata{
		Mode:           MaterializationLocal,
		SourceID:       "service-example",
		RootHash:       manifest.ContentHash,
		ResolvedCommit: manifest.ResolvedRevision,
		CreatedAt:      "2026-10-16T00:00:00Z",
	}
	s0 := goodStage0()
	s0.Input = in
	s0.Snapshot = manifest
	s0.Source = MaterializedSource{Root: repoDir, Metadata: manifest.Materialization, Cleanup: func() error { return nil }}
	s0.Proposal.VulnerabilityIDs = []string{"CVE-2025-1234"}
	s0.Advisory.ID, s0.Advisory.ResolvedID = "CVE-2025-1234", "CVE-2025-1234"
	advisoryPath := filepath.Join(t.TempDir(), "CVE-2025-1234.json")
	writeFile(t, advisoryPath, `{"id":"CVE-2025-1234","summary":"example advisory"}`)
	s0.Advisory.Path = advisoryPath
	s0.Advisory.SHA256 = sha256Hex(t, mustRead(t, advisoryPath))
	s0.Advisory.Size = int64(len(mustRead(t, advisoryPath)))
	s0.Advisory.FrozenAt = "2026-10-16T00:00:00Z"
	if s0.Resolution != nil {
		s0.Resolution.Vulnerability.ID = "CVE-2025-1234"
		s0.Resolution.Vulnerability.AffectedSymbols = []domain.SymbolRef{{Package: "example.com/dep", Symbol: "Fn"}}
		s0.Resolution.Projection.AffectedSymbols = []domain.SymbolRef{{Package: "example.com/dep", Symbol: "Fn"}}
		s0.Resolution.Record = s0.Advisory
	}
	for i := range s0.Validation.Fields {
		if s0.Validation.Fields[i].Field == "vulnerability_ids" {
			s0.Validation.Fields[i].Value = "CVE-2025-1234"
		}
	}
	s0.Materials.Materials = []Material{{
		ID: "mat-module-graph", Kind: MaterialModuleGraph, Source: "go list -m all",
		Scope: "build-graph", Availability: MaterialAvailable,
	}}

	condID := AdvisoryConditionID("CVE-2025-1234")
	proposal := FalsifierProposal{
		ID: "fp-1", ClaimID: "c1", ConditionID: condID, Kind: FalsifierCodeAbsent,
		Subjects:     []FalsifierSubject{{Package: "example.com/dep", Symbol: "Fn"}},
		EvidenceRefs: []string{"e1"},
	}
	// Attempt 1: accepted but proposal-free answer.
	agentA1 := Assessment{
		SchemaVersion:  AssessmentSchemaVersion,
		FindingID:      in.Finding.FindingID,
		Verdict:        VerdictNotExploitable,
		Summary:        "attempt 1: no proposal",
		Claims:         []Claim{refClaim("c1", "e1")},
		Evidence:       []EvidenceRef{{ID: "e1", Kind: "det", Locator: "det:det-0001"}},
		ProposedAction: closeAction("c1"),
	}
	agentA1JSON, err := json.Marshal(agentA1)
	if err != nil {
		t.Fatal(err)
	}
	// Attempt 2: the proposal cites this attempt's own observation id
	// (det-a2-0001): the attempt-qualified id space a retry's tools
	// record into.
	agentA2 := agentA1
	agentA2.Summary = "attempt 2: verified proposal"
	agentA2.Evidence = []EvidenceRef{{ID: "e1", Kind: "det", Locator: "det:det-a2-0001"}}
	agentA2.FalsifierProposals = []FalsifierProposal{proposal}
	agentA2JSON, err := json.Marshal(agentA2)
	if err != nil {
		t.Fatal(err)
	}
	subj, _ := json.Marshal([]FalsifierSubject{{Package: "example.com/dep", Symbol: "Fn"}})
	caArgs, _ := json.Marshal(map[string]any{"subjects": json.RawMessage(subj)})

	agentIn := Stage0AgentFinding(in, s0.AdvisoryVulnerability())
	inventory, _ := currentInventoryFixture(manifest.ContentHash)
	bctx := inventory.InventoryScope
	detObs := &evidencetools.Observation{
		ID:           "ev-ca",
		Tool:         "verify_code_absence",
		Fact:         "closure-backed absence",
		Scope:        "product packages",
		Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		Data: map[string]any{
			"absent_subjects":       []map[string]string{{"package": "example.com/dep", "symbol": "Fn"}},
			"checked_subjects":      []map[string]string{{"package": "example.com/dep", "symbol": "Fn"}},
			"expected_subjects":     []map[string]string{{"package": "example.com/dep", "symbol": "Fn"}},
			"coverage_rule_version": evidencetools.CodeAbsenceCoverageRuleVersion,
			"import_closure": map[string]any{
				"inventory_raw":inventory.InventoryRaw, "inventory_reference":inventory.InventoryReference,
				"inventory_build":inventory.InventoryBuild, "inventory_run":inventory.InventoryRun, "inventory_scope":inventory.InventoryScope,
				"complete": true, "hash": "closure-hash-1", "scope_hash": "scope-hash-1",
				"scope_rule": evidencetools.CodeAbsenceScopeRule, "scope_complete": true,
				"dynamic_relevance_rule":     evidencetools.CodeAbsenceDynamicRule,
				"dynamic_relevance_complete": true,
				"shipping_roots":             []string{"cmd/app"},
				"package_states":             map[string]string{"cmd/app": "LIVE"},
			},
		},
		ScopeDetails: &evidencetools.ScopeDetails{
			SnapshotHash: manifest.ContentHash,
			BuildContext: bctx,
		},
	}

	// Attempt 1 tooling: its store stamps attempt 1 (unqualified det ids).
	store1 := NewRunObservationStore(AttemptRunID(in.Finding.FindingID, 1), 1)
	det1 := &DeterministicTools{
		Caller:           &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) { return detObs, nil }},
		Catalog:          CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog()),
		ObservationStore: store1,
	}
	tools1 := &ToolSet{Parts: []ToolExecutor{
		&ReadOnlyTools{Snapshot: manifest, Finding: agentIn, Advisory: s0.AdvisoryProjection()},
		det1,
	}}
	run1, err := AgentRunner{Client: &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: string(agentA1JSON)}}},
		Tools: tools1, Materials: BuildAgentMaterials(s0.Materials), Limits: AgentLimits{MaxSteps: 4}}.Run(ctx, agentIn, manifest)
	if err != nil {
		t.Fatalf("run attempt 1: %v", err)
	}
	// Attempt 2 tooling: fresh executor and attempt-2-stamped store —
	// observations land under det-a2-* ids and this attempt's run id.
	store2 := NewRunObservationStore(AttemptRunID(in.Finding.FindingID, 2), 2)
	det2 := &DeterministicTools{
		Caller:           &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) { return detObs, nil }},
		Catalog:          CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog()),
		ObservationStore: store2,
	}
	tools2 := &ToolSet{Parts: []ToolExecutor{
		&ReadOnlyTools{Snapshot: manifest, Finding: agentIn, Advisory: s0.AdvisoryProjection()},
		det2,
	}}
	run2, err := AgentRunner{Client: &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", ToolCalls: []llm.ToolCall{{
			ID: "call-1", Type: "function",
			Function: llm.FunctionCall{Name: "verify_code_absence", Arguments: string(caArgs)},
		}}},
		{Role: "assistant", Content: string(agentA2JSON)},
	}}, Tools: tools2, Materials: BuildAgentMaterials(s0.Materials), Limits: AgentLimits{MaxSteps: 4}}.Run(ctx, agentIn, manifest)
	if err != nil {
		t.Fatalf("run attempt 2: %v", err)
	}
	// Freeze each attempt's archive exactly the way the CLI does: the
	// run record's Observations carry this attempt's full archive view.
	run1.Observations = store1.Observations()
	run2.Observations = store2.Observations()

	gate := FactGate{Observations: ObservationIndex(tools2.AuditEvents())}
	fv2 := gate.Validate(ctx, agentIn, manifest, run2.Assessment)
	if fv2.Status != ValidationComplete {
		t.Fatalf("attempt-2 gate = %s, want COMPLETE (%+v)", fv2.Status, fv2)
	}
	// The catalog the live run bound to: condition condID mandatory,
	// code_absence allowed.
	cat := &ConditionCatalog{
		SchemaVersion:   ConditionCatalogSchemaVersion,
		CatalogID:       "cat-run-1",
		AdvisoryID:      "CVE-2025-1234",
		AdvisoryDigest:  s0.Advisory.SHA256,
		CaseIdentityRef: in.Finding.FindingID,
		Conditions: []CatalogCondition{{
			ConditionID:           condID,
			Kind:                  "code_absence",
			Mandatory:             true,
			CheckerID:             "advisory-code-absence",
			CheckerVersion:        "1",
			AllowedFalsifierKinds: []FalsifierKind{FalsifierCodeAbsent},
			CoverageRule:          "every mandatory subject must resolve inside the snapshot",
		}},
	}
	cat.Sign()
	binding := runBindingFor(cat)

	// Mint the verified report the live attempt-2 falsifier pass would
	// produce — the real verifier over this attempt's archive, never a
	// hand-shaped fixture.
	build := ""
	for _, o := range run2.Observations {
		if o.BuildContextHash != "" {
			build = o.BuildContextHash
			break
		}
	}
	var symbols []FalsifierSubject
	for _, s := range s0.Resolution.Projection.AffectedSymbols {
		symbols = append(symbols, FalsifierSubject{Package: s.Package, Symbol: s.Symbol})
	}
	source, err := NewAdvisoryConditionSource(AdvisoryConditionOptions{
		AdvisoryID: "CVE-2025-1234", Module: "example.com/dep", ResolvedVersion: "v1.0.0",
		SnapshotHash: manifest.ContentHash, BuildContextHash: build,
		RuleID: "advisory-code-absence", RuleVersion: "1", RuleSetHash: strings.Repeat("07", 32),
		Symbols: symbols,
	})
	if err != nil {
		t.Fatalf("condition source: %v", err)
	}
	admission := GateFalsifierProposals(cat, binding, run2.Assessment.FalsifierProposals)
	if len(admission.Admitted) != 1 {
		t.Fatalf("proposal not admitted: %+v", admission.Rejected)
	}
	report := NewFalsifierVerifier(source).Verify(ctx, FalsifierVerificationInput{
		Stage0: s0, Assessment: run2.Assessment, FactValidation: fv2,
		Proposals: admission.Admitted, Observations: run2.Observations,
		RulesetHash: strings.Repeat("07", 32), ExpectedRulesetHash: strings.Repeat("07", 32),
		RunID: AttemptRunID(in.Finding.FindingID, 2), Attempt: 2,
	})
	if len(report.Proofs) != 1 || report.Proofs[0].Status != FalsifierVerified {
		t.Fatalf("attempt-2 report not VERIFIED: reason=%q proofs=%+v", report.Proofs[0].Reason, report.Proofs)
	}

	// Assemble the persisted run: the primary transcript stays attempt 1;
	// run2 rides stability_runs; assessment/decision/stability pin the
	// retry — exactly what runTriageFinding writes for a selected retry.
	primary := run1
	primary.Attempts = []AgentRun{run2}
	a2Stored := run2.Assessment
	a2Stored.FactValidation = fv2.Status
	a2Stored.FactValidationDetail = &fv2
	w := ArtifactWriter{Clock: clock, Model: "test-model", ToolVersions: map[string]string{"izyan": "test"}}
	if _, err := w.WriteStage0Artifacts(ctx, outDir, s0); err != nil {
		t.Fatalf("WriteStage0Artifacts: %v", err)
	}
	// Attempt-tagged audit event so the replay fact gate resolves
	// det:det-a2-0001 against attempt 2's tool call.
	var auditEvents []AuditEvent
	for _, tev := range ToolAuditEvents(det2.AuditEvents(), time.Now().UTC()) {
		tev.Attempt = 2
		auditEvents = append(auditEvents, tev)
	}
	art, err := w.Write(ctx, outDir, in, manifest, primary, a2Stored, append(s0.Events, auditEvents...), &run2)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	stabReport := StabilityReport{
		Retries:         1,
		SelectedAttempt: 2,
		Stable:          true,
		Attempts: []StabilityAttempt{
			{
				Attempt: 1, Judgment: string(VerdictNotExploitable), ActionKind: string(HumanActionClose),
				ActionScope: "captured build", SupportLevel: string(SupportLevelSubstantiated),
				Recommendation: RecommendationUnchanged, ProfileID: "p",
				InputHash: in.SHA256, SnapshotHash: manifest.ContentHash, PromptHash: primary.PromptHash,
			},
			{
				Attempt: 2, Judgment: string(VerdictNotExploitable), ActionKind: string(HumanActionClose),
				ActionScope: "captured build", SupportLevel: string(SupportLevelSubstantiated),
				Recommendation: RecommendationUnchanged, ProfileID: "p",
				InputHash: in.SHA256, SnapshotHash: manifest.ContentHash, PromptHash: run2.PromptHash,
			},
		},
	}
	if err := w.WriteStability(ctx, art.RootDir, in.Finding.FindingID, art.RunID, stabReport); err != nil {
		t.Fatalf("WriteStability: %v", err)
	}
	if err := w.WriteFalsifierReport(ctx, art.RootDir, report); err != nil {
		t.Fatalf("WriteFalsifierReport: %v", err)
	}
	if err := w.WriteConditionCatalog(ctx, art.RootDir, cat, binding); err != nil {
		t.Fatalf("WriteConditionCatalog: %v", err)
	}
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	pkg, err := Composer{
		RulesetHash: strings.Repeat("07", 32),
		Stability:   &stabReport,
		Limits:      BudgetConfig{MaxLLMSteps: 32, MaxToolCalls: 128, MaxSourceBytes: 1 << 20, TimeoutSeconds: 900},
	}.ComposeWithEvidence(ctx, s0, stored, *stored.FactValidationDetail, EvidenceInput{Observations: run2.Observations, Falsifiers: &report})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := w.WriteDecision(ctx, outDir, pkg); err != nil {
		t.Fatalf("WriteDecision: %v", err)
	}
	return art.RootDir
}

// TestReplaySelectedAttemptVerifiedProof is the P1 pin: a run whose
// decision composed from a stability retry must replay that attempt —
// byte-identically — while the foreign attempt's observations stay out
// of the recomputed verifier. The fixture's primary attempt cites
// det:det-0001 while the selected attempt's proof binds det:det-a2-0001;
// passing means the merged archive never leaked attempt 1's evidence
// into the retry's re-verification and the recorded pin resolved the
// canonical attempt without hash-scan guesswork.
func TestReplaySelectedAttemptVerifiedProof(t *testing.T) {
	runDir := recordTwoAttemptProposalRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	rep, err := PrepareReplay(context.Background(), runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if rep.Assessment.Verdict != VerdictNotExploitable {
		t.Fatalf("replayed verdict %q, want %q", rep.Assessment.Verdict, VerdictNotExploitable)
	}
	if rep.Decision == nil {
		t.Fatal("replay produced no decision")
	}
	// The recomposed package must carry the persisted VERIFIED proof —
	// replay recomputes it from the selected attempt's archive, so a
	// non-VERIFIED recompute would have failed the drift check already.
	var found bool
	for _, p := range rep.RecomputedFalsifier.Proofs {
		if p.ProposalID == "fp-1" && p.Status == FalsifierVerified {
			found = true
		}
	}
	if !found {
		t.Fatalf("recomputed falsifier report lacks the VERIFIED fp-1 proof")
	}
}

// TestReplaySelectedAttemptRejectsForeignObservation proves the filter's
// negative half: corrupt attempt 1's archive entry so it still parses but
// claims the proposal's evidence id — a foreign-attempt record that must
// never satisfy the retry's citation. Recompute uses only attempt-2
// records, so the replay stays byte-identical rather than drifting or
// admitting borrowed evidence.
func TestReplaySelectedAttemptRejectsForeignObservation(t *testing.T) {
	runDir := recordTwoAttemptProposalRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	// Rewrite attempt 1's archive entry so it claims to establish the
	// proposal's proof — if replay passed the merged archive to the
	// verifier, this foreign record could bind attempt 2's proof.
	archivePath := filepath.Join(runDir, "observation-archive.json")
	a, err := ReadObservationArchive(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.Observations {
		if a.Observations[i].Attempt == 1 {
			// Give the attempt-1 record the same tool and a *different*
			// RunID the verifier must reject outright; keep it parseable.
			a.Observations[i].ID = "det-0001"
			a.Observations[i].RunID = AttemptRunID("scanner-123", 1)
		}
	}
	// Persist through the canonical writer so hashing stays consistent.
	if err := os.Remove(archivePath); err != nil {
		t.Fatal(err)
	}
	if err := WriteObservationArchive(context.Background(), archivePath, observationSliceStore{items: a.Observations}); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), runDir); err != nil {
		t.Fatalf("replay must ignore foreign-attempt observations, got: %v", err)
	}
}

// TestReplayLegacyUnboundRefusesProof: a legacy run that persisted
// condition-catalog.json but not catalog-binding.json has no verifiable
// hash pin — proof-bearing replay must refuse with the named error
// instead of silently accepting a derived binding. The strict default
// (PrepareReplay) keeps the unverifiable-pin drift from slipping through.
func TestReplayLegacyUnboundRefusesProof(t *testing.T) {
	cat := runCatalog(t, fixtureAdvisoryDigest(t), "scanner-123")
	runDir := recordProposalRun(t, newReplayRepo(t), t.TempDir(), replayClockA, cat, runBindingFor(cat))
	// Simulate the legacy persistence shape: catalog present, binding gone.
	if err := os.Remove(filepath.Join(runDir, "catalog-binding.json")); err != nil {
		t.Fatal(err)
	}
	_, err := PrepareReplay(context.Background(), runDir)
	if err == nil {
		t.Fatal("legacy proof-bearing replay without binding must refuse")
	}
	if !errors.Is(err, ErrLegacyCatalogUnbound) {
		t.Fatalf("refusal must wrap ErrLegacyCatalogUnbound, got: %v", err)
	}
}

// TestReplayLegacyUnboundOptIn: with the explicit AllowLegacyUnboundBinding
// the same run replays under the derived pin — but the weakened provenance
// is recorded in the report's limitations, never silent.
func TestReplayLegacyUnboundOptIn(t *testing.T) {
	// Two-attempt fixture: the persisted report is the verifier's own
	// output, so an honest catalog replays byte-identical once the
	// derived binding admits it.
	runDir := recordTwoAttemptProposalRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	if err := os.Remove(filepath.Join(runDir, "catalog-binding.json")); err != nil {
		t.Fatal(err)
	}
	rep, err := PrepareReplayWithOptions(context.Background(), runDir, ReplayOptions{AllowLegacyUnboundBinding: true})
	if err != nil {
		t.Fatalf("opted-in legacy replay must proceed, got: %v", err)
	}
	found := false
	for _, l := range rep.Limitations {
		if strings.Contains(l, "derived pin") || strings.Contains(l, "catalog-binding") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("opted-in replay must record the derived-pin limitation, got: %+v", rep.Limitations)
	}
	// The derived pin still enforces content: the honest catalog admits
	// the proposal and the recompute carries the persisted VERIFIED proof.
	var verified bool
	for _, p := range rep.RecomputedFalsifier.Proofs {
		if p.ProposalID == "fp-1" && p.Status == FalsifierVerified {
			verified = true
		}
	}
	if !verified {
		t.Fatalf("opted-in replay recomputed %+v, want VERIFIED fp-1", rep.RecomputedFalsifier.Proofs)
	}
}

// TestReplayLegacyNoProofUnaffected: a legacy run with a catalog but no
// proof surface (no proposals, no persisted report) never reaches the
// binding path — the strict default replays it without the opt-in.
func TestReplayLegacyNoProofUnaffected(t *testing.T) {
	repoDir := newReplayRepo(t)
	fx := recordReplayRun(t, repoDir, t.TempDir(), "test-model", replayClockA, replayClockA)
	// The plain fixture writes no catalog — inject one to emulate legacy
	// run shape; it must be ignored when no proof surface exists.
	cat := runCatalog(t, fixtureAdvisoryDigest(t), "scanner-123")
	raw, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.runDir, "condition-catalog.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), fx.runDir); err != nil {
		t.Fatalf("non-proof legacy run must replay without the opt-in, got: %v", err)
	}
}

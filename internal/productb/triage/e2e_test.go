package triage_test

// S-10 E2E chain gate: finding.v1 → snapshot → detools (live kernel session)
// → assessment.v2 (proposal-only) → FactGate det:/obs: → falsifier verify →
// DecisionPackage → policy → persist → fail-closed replay → verify.Evaluate.
// Every hop is the real ported code path; the only scripted piece is the
// model's chat replies (no network, no LLM).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/llm"
	"github.com/davniy/izyan/internal/productb/claimshape"
	domain "github.com/davniy/izyan/internal/productb/domain"
	triage "github.com/davniy/izyan/internal/productb/triage"
	"github.com/davniy/izyan/internal/productb/verify"
	"github.com/davniy/izyan/internal/productb/vulnerability"
)

var e2eClock = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }

// e2eChat is the scripted ChatClient: message 1 carries the kernel tool
// call, message 2 the final assessment.v2 payload.
type e2eChat struct {
	responses []llm.ChatMessage
	calls     int
}

func (c *e2eChat) Chat(_ context.Context, _ llm.ModelRole, _ string, _ []llm.ChatMessage, _ []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	if c.calls >= len(c.responses) {
		return llm.ChatMessage{Role: "assistant", Content: `{"schema_version":"`+triage.AssessmentSchemaVersion+`","verdict":"INCONCLUSIVE","summary":"out of script","claims":[{"id":"c1","statement":"the scripted material was exhausted","basis":"UNRESOLVED","subject":"investigation completeness","scope":"scripted fixture","reason":"the response script ended","decision_relevant":true}],"proposed_action":{"kind":"OBTAIN_EVIDENCE","instruction":"continue the investigation","rationale":"the scripted material ended before a conclusion","scope":"scripted fixture","decisive_claim_ids":["c1"],"reconsider_when":["the investigation completes"]}}`}, "stop", nil
	}
	m := c.responses[c.calls]
	c.calls++
	return m, "stop", nil
}

// e2eKernelSession opens a real evidencetools session over the recorded
// unreachability fixture — the same session shape the production adapter
// binds through ClientCaller.
func e2eKernelSession(t *testing.T) *evidencetools.Session {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "e2e-product"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := evidencetools.NewSession(evidencetools.SessionConfig{
		SnapshotRoot: root, Audit: evidencetools.NopAudit{}, GOOS: "darwin", GOARCH: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// e2eStage0 builds the Stage 0 projection the kernel run binds to: the
// vulnerable module resolved at an affected version, the advisory
// projection declaring the two orphan symbols, a verified intake proposal.
func e2eStage0(t *testing.T, in triage.FindingInput, manifest triage.SnapshotManifest, snapshotHash string) triage.Stage0Result {
	t.Helper()
	vuln := domain.Vulnerability{
		ID:           "CVE-2099-0001",
		Module:       "example.org/ghostpkg",
		Package:      "example.org/ghostpkg",
		BaseSeverity: "HIGH", BaseScore: 7.5,
		AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "v0.9.9"}},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.org/ghostpkg", Symbol: "GhostFn"},
		},
	}
	return triage.Stage0Result{
		Input:        in,
		Snapshot:     manifest,
		CatalogEntry: triage.CatalogEntry{ID: "sessionprod", Kind: "local", Root: in.Finding.Target.Repository, Ecosystem: "go"},
		CandidateRefs: []triage.RefCandidate{
			{ID: "cand-1", Name: "v0.5.0", Kind: triage.RefTag, Commit: manifest.ResolvedRevision, Source: "sessionprod"},
		},
		SelectedRef: triage.RefCandidate{ID: "cand-1", Name: "v0.5.0", Kind: triage.RefTag, Commit: manifest.ResolvedRevision, Source: "sessionprod"},
		RefResolution: triage.RefResolution{
			SelectedID: "cand-1", SelectedRef: "v0.5.0",
			ResolvedCommit: manifest.ResolvedRevision, ResolutionRule: triage.RefRuleExact,
		},
		Proposal: triage.IntakeProposal{
			SchemaVersion:    triage.IntakeProposalSchemaVersion,
			VulnerabilityIDs: []string{"CVE-2099-0001"},
			Package:          "example.org/ghostpkg",
			Version:          "v0.5.0",
			Severity:         "high",
		},
		Validation: triage.IntakeValidation{Fields: []triage.FieldValidation{
			{Field: "vulnerability_ids", Status: triage.IntakeValid, Value: "CVE-2099-0001", Provenance: []string{"raw_text"}},
			{Field: "package", Status: triage.IntakeValid, Value: "example.org/ghostpkg", Provenance: []string{"catalog"}},
			{Field: "severity", Status: triage.IntakeValid, Value: "high", Provenance: []string{"advisory"}},
		}},
		Advisory: vulnerability.FrozenAdvisory{
			Source: "osv", SHA256: strings.Repeat("ab", 32), ResolvedID: "CVE-2099-0001",
		},
		Resolution: &triage.AdvisoryResolution{
			Vulnerability: &vuln,
			Projection:    triage.AdvisoryProjectionFromVulnerability(vuln),
			Record: vulnerability.FrozenAdvisory{
				Source: "osv", SHA256: strings.Repeat("ab", 32), ResolvedID: "CVE-2099-0001",
			},
		},
		PackageCheck: triage.PackageCheckResult{
			Class:           triage.CheckAffectedRange,
			ClaimedPath:     "example.com/sessiondep",
			ClaimedVersion:  "v0.5.0",
			ResolvedPath:    "example.com/sessiondep",
			ResolvedVersion: "v0.5.0",
			EvidenceSource:  "module_graph",
			Provenance:      []string{"go.mod"},
		},
		Materials: triage.MaterialSet{Materials: []triage.Material{{
			ID: "mat-module-graph", Kind: triage.MaterialModuleGraph, Source: "go list -m all",
			Scope: "build-graph", Availability: triage.MaterialAvailable,
		}}},
		Source: triage.MaterializedSource{
			Root: in.Finding.Target.Repository,
			Metadata: triage.MaterializationMetadata{
				Mode: triage.MaterializationLocal, SourceID: "sessionprod",
				SelectedRef: "v0.5.0", ResolvedCommit: manifest.ResolvedRevision,
				RootHash: manifest.ContentHash, CreatedAt: "2026-10-15T00:00:00Z",
			},
		},
		Raw: triage.RawIntake{Raw: in.Raw, TicketHash: in.SHA256, Format: triage.IntakeJSON},
	}
}

func e2eFalsifierSource(subjects []triage.FalsifierSubject, snapshotHash, buildHash string) triage.MandatoryConditionSource {
	src, err := triage.NewAdvisoryConditionSource(triage.AdvisoryConditionOptions{
		AdvisoryID:       "CVE-2099-0001",
		Module:           "example.com/sessiondep",
		ResolvedVersion:  "v0.5.0",
		SnapshotHash:     snapshotHash,
		BuildContextHash: buildHash,
		RuleID:           "advisory-code-absence",
		RuleVersion:      "1",
		RuleSetHash:      "e2e-ruleset",
		Symbols:          subjects,
	})
	if err != nil {
		return nil
	}
	return src
}

// TestE2ETriageChain runs the S-07/S-10 gate end to end over a live kernel
// session and asserts every boundary the merge requires: proposal-only
// ingress, observation-bound facts, deterministic dismissal, separate
// policy, byte-identical replay and the universal verification pass.
func TestE2ETriageChain(t *testing.T) {
	ctx := context.Background()
	sess := e2eKernelSession(t)
	root := filepath.Join("..", "..", "testdata", "e2e-product")
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}

	// --- finding.v1 ingress ---
	findingJSON := `{"schema_version":"finding.v1","finding_id":"e2e-001",` +
		`"vulnerability":{"ids":["CVE-2099-0001"]},"component":{"name":"ghost","package":"example.org/ghostpkg","version":"v0.5.0"},` +
		`"target":{"repository":` + strconv(absRoot) + `,"revision":"v0.5.0"},"scanner":{"severity":"high"}}`
	findings, err := triage.ParseFindings(strings.NewReader(findingJSON))
	if err != nil || len(findings) != 1 {
		t.Fatalf("ParseFindings: %v (n=%d)", err, len(findings))
	}
	in := findings[0]

	manifest, err := triage.LocalSnapshotBuilder{Now: e2eClock}.Build(ctx, in)
	if err != nil {
		t.Fatalf("snapshot build: %v", err)
	}

	// --- detools over the live kernel session ---
	client, err := sess.Connect(ctx)
	if err != nil {
		t.Fatalf("session connect: %v", err)
	}
	defer client.Close()
	det := &triage.DeterministicTools{
		Caller:           triage.ClientCaller{Client: client},
		Catalog:          triage.CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog()),
		ObservationStore: triage.NewRunObservationStore(triage.AttemptRunID(in.Finding.FindingID, 1), 1),
	}
	advPath := filepath.Join(t.TempDir(), "CVE-2099-0001.json")
	if err := os.WriteFile(advPath, []byte(`{"id":"CVE-2099-0001","summary":"e2e advisory"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s0 := e2eStage0(t, in, manifest, manifest.ContentHash)
	advData := mustReadFile(t, advPath)
	s0.Advisory.Path, s0.Advisory.ID = advPath, "CVE-2099-0001"
	s0.Advisory.SHA256 = sha256Hex(advData)
	s0.Advisory.Size = int64(len(advData))
	s0.Advisory.FrozenAt = "2026-10-15T00:00:00Z"
	s0.Resolution.Record = s0.Advisory
	agentIn := triage.Stage0AgentFinding(in, s0.AdvisoryVulnerability())
	toolset := &triage.ToolSet{Parts: []triage.ToolExecutor{
		&triage.ReadOnlyTools{Snapshot: manifest, Finding: agentIn, Advisory: s0.AdvisoryProjection()},
		det,
	}}
	subjects := []triage.FalsifierSubject{{Package: "example.org/ghostpkg", Symbol: "GhostFn"}}

	// --- assessment.v2: scripted agent calls the kernel tool once, then
	// returns an assessment citing det:det-0001, a concrete human action and
	// a falsifier proposal bound to the mandatory condition ---
	subj, _ := json.Marshal(subjects)
	caArgs, _ := json.Marshal(map[string]any{"subjects": json.RawMessage(subj)})
	agentAssessment := map[string]any{
		"schema_version": triage.AssessmentSchemaVersion,
		"finding_id":     in.Finding.FindingID,
		"verdict":        "NOT_EXPLOITABLE",
		"summary":        "declared vulnerable symbols are unreachable in the recorded product scope",
		"claims": []map[string]any{{
			"id": "c1", "statement": "no invocation of OrphanA/OrphanB exists in the recorded scope",
			"basis": "PROVED", "subject": "declared vulnerable symbols", "scope": "recorded product scope",
			"decision_relevant": true, "evidence_refs": []string{"ev-1"},
		}},
		"evidence": []map[string]any{{
			"id": "ev-1", "kind": "det", "locator": "det:det-0001",
		}},
		"proposed_action": map[string]any{
			"kind": "CLOSE", "instruction": "close the ticket as not exploitable",
			"rationale": "the declared vulnerable symbols have no invocation in the recorded scope",
			"scope":     "recorded product scope", "decisive_claim_ids": []string{"c1"},
			"reconsider_when": []string{"an invocation of a declared vulnerable symbol is captured"},
		},
		"falsifier_proposals": []map[string]any{{
			"id": "fp-1", "claim_id": "c1", "condition_id": "cond-CVE-2099-0001",
			"kind":          string(triage.FalsifierCodeAbsent),
			"subjects":      json.RawMessage(subj),
			"evidence_refs": []string{"ev-1"},
		}},
	}
	agentJSON, err := json.Marshal(agentAssessment)
	if err != nil {
		t.Fatal(err)
	}
	chat := &e2eChat{responses: []llm.ChatMessage{
		{Role: "assistant", ToolCalls: []llm.ToolCall{{
			ID: "call-1", Type: "function",
			Function: llm.FunctionCall{Name: "verify_code_absence", Arguments: string(caArgs)},
		}}},
		{Role: "assistant", Content: string(agentJSON)},
	}}
	run, fv, err := triage.AgentRunner{Client: chat, Tools: toolset, Materials: triage.BuildAgentMaterials(s0.Materials), Limits: triage.AgentLimits{MaxSteps: 8}}.
		RunWithFactGate(ctx, agentIn, manifest, triage.FactGate{}, 2)
	if err != nil {
		t.Fatalf("agent run: %v", err)
	}
	if fv.Status != triage.ValidationComplete {
		t.Fatalf("fact gate = %s (refs=%+v)", fv.Status, fv.References)
	}
	// det:<id> bound to the recorded kernel observation — a reproducible
	// reference, asserted VALID (never proof).
	var detRef *triage.ReferenceCheck
	for i := range fv.References {
		if fv.References[i].EvidenceID == "ev-1" {
			detRef = &fv.References[i]
		}
	}
	if detRef == nil || detRef.Status != triage.FactValid || detRef.Tool != "verify_code_absence" {
		t.Fatalf("det: reference check = %+v", detRef)
	}

	assessment := run.Assessment
	assessment.FactValidation = fv.Status
	assessment.FactValidationDetail = &fv

	// --- deterministic falsifier verification (proposal-only) ---
	store, _ := toolset.Parts[1].(*triage.DeterministicTools)
	obs := store.ObservationStore.(triage.ObservationStore).Observations()
	if len(obs) != 1 || obs[0].Tool != "verify_code_absence" {
		t.Fatalf("recorded observations = %+v", obs)
	}
	src, serr := triage.NewAdvisoryConditionSource(triage.AdvisoryConditionOptions{
		AdvisoryID: "CVE-2099-0001", Module: "example.org/ghostpkg", ResolvedVersion: "v0.5.0",
		SnapshotHash: obs[0].SnapshotHash, BuildContextHash: obs[0].BuildContextHash,
		RuleID: "advisory-code-absence", RuleVersion: "1", RuleSetHash: "e2e-ruleset",
		Symbols: subjects,
	})
	if serr != nil {
		t.Fatalf("condition source: %v", serr)
	}
	report := triage.NewFalsifierVerifier(src).Verify(ctx, triage.FalsifierVerificationInput{
		Stage0: s0, Assessment: assessment, FactValidation: fv,
		Proposals: assessment.FalsifierProposals, Observations: obs,
		RulesetHash: "e2e-ruleset", ExpectedRulesetHash: "e2e-ruleset",
		RunID: triage.AttemptRunID(in.Finding.FindingID, 1), Attempt: 1,
	})
	if len(report.Proofs) != 1 || report.Proofs[0].Status != triage.FalsifierVerified {
		t.Fatalf("falsifier proof = %+v", report.Proofs)
	}
	// The package's audit pin reproduces the assessment audit fields the
	// artifact writer stamps at persist time; compose on the same audit so
	// replay recomposition is byte-identical.
	assessment.Audit = &triage.AssessmentAudit{
		FindingHash: in.SHA256, SnapshotHash: manifest.ContentHash,
		PromptHash: run.PromptHash, Model: "e2e",
		ToolVersions: map[string]string{"izyan": "test"}, DetTools: run.DetTools,
	}
	{
		pkg, err := triage.Composer{RunID: "e2e-run", ExecutionMode: "single", RulesetHash: "e2e-ruleset"}.
			ComposeWithEvidence(ctx, s0, assessment, fv, triage.EvidenceInput{Observations: obs, Falsifiers: &report})
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		t.Logf("baseline=%+v", pkg.MachineDisposition.Baseline)
		if pkg.MachineDisposition.Recommendation != triage.RecommendationDismissed {
			t.Fatalf("recommendation = %s (demotions=%v)",
				pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Demotions)
		}
		// --- the human result travels with the machine reduction ---
		if pkg.Judgment.Verdict != triage.VerdictNotExploitable ||
			pkg.ProposedAction.Kind != triage.HumanActionClose ||
			pkg.ProposedAction.Instruction == "" {
			t.Fatalf("human axes were not preserved: judgment=%+v action=%+v", pkg.Judgment, pkg.ProposedAction)
		}
		if pkg.Scope.Boundary != triage.DecisionBoundaryExactRecords ||
			len(pkg.Scope.Records) != 1 ||
			pkg.Scope.Records[0].ID != "CVE-2099-0001" ||
			pkg.Scope.Records[0].SHA256 != s0.Advisory.SHA256 ||
			pkg.Scope.SnapshotHash != manifest.ContentHash {
			t.Fatalf("decision scope is not record-bound: %+v", pkg.Scope)
		}
		if len(pkg.Premises) == 0 || pkg.Support.Level == "" || len(pkg.Support.DecisiveClaimIDs) != len(pkg.Premises) {
			t.Fatalf("premise/support axes are incomplete: premises=%+v support=%+v", pkg.Premises, pkg.Support)
		}
		if len(pkg.FalsifierProofs) != 1 || pkg.FalsifierProofs[0].Status != triage.FalsifierVerified {
			t.Fatalf("admitted proof missing from the package: %+v", pkg.FalsifierProofs)
		}
		card := string(triage.RenderDecisionMarkdown(pkg))
		for _, want := range []string{
			"## Proposed action (human)", "## Why this action", "## Decision scope",
			"no CVE-wide statement", s0.Advisory.SHA256,
			"## Accept or reject this proposal (human decision)", "## Machine disposition (deterministic)",
		} {
			if !strings.Contains(card, want) {
				t.Fatalf("action card lacks %q:\n%s", want, card)
			}
		}
		// --- policy stays outside the package ---
		if triage.PackagePolicyHit(pkg, triage.FailOnUnchanged) {
			t.Fatal("DISMISSED package must not trip the unchanged threshold")
		}
		// --- persistence + fail-closed replay ---
		outDir := t.TempDir()
		w := triage.ArtifactWriter{Clock: e2eClock, Model: "e2e", ToolVersions: map[string]string{"izyan": "test"}}
		if _, err := w.WriteStage0Artifacts(ctx, outDir, s0); err != nil {
			t.Fatalf("WriteStage0Artifacts: %v", err)
		}
		events := append(
			[]triage.AuditEvent{{Type: triage.AuditEventRunStarted, Status: "ok"}},
			append(s0.Events, triage.ToolAuditEvents(det.AuditEvents(), e2eClock().UTC())...)...,
		)
		art, err := w.Write(ctx, outDir, in, manifest, run, assessment, events, nil)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.WriteFalsifierReport(ctx, art.RootDir, report); err != nil {
			t.Fatalf("WriteFalsifierReport: %v", err)
		}
		// The live CLI persists the catalog pair next to the report; the
		// fixture mirrors it so replay re-admits the proposal against the
		// recorded binding instead of failing closed.
		cat := &triage.ConditionCatalog{
			SchemaVersion:   triage.ConditionCatalogSchemaVersion,
			CatalogID:       "cat-e2e",
			AdvisoryID:      "CVE-2099-0001",
			AdvisoryDigest:  s0.Advisory.SHA256,
			CaseIdentityRef: in.Finding.FindingID,
			Conditions: []triage.CatalogCondition{{
				ConditionID:           "cond-CVE-2099-0001",
				Kind:                  "code_absence",
				Mandatory:             true,
				Subjects:              []triage.CatalogSubject{{Package: "example.org/ghostpkg", Symbol: "GhostFn", Role: "mandatory-control"}},
				CheckerID:             "advisory-code-absence",
				CheckerVersion:        "1",
				AllowedFalsifierKinds: []triage.FalsifierKind{triage.FalsifierCodeAbsent},
				CoverageRule:          "every mandatory subject must resolve inside the snapshot",
			}},
		}
		cat.Sign()
		e2eBinding := triage.CatalogBinding{
			AdvisoryID:          cat.AdvisoryID,
			AdvisoryDigest:      cat.AdvisoryDigest,
			CaseIdentityRef:     cat.CaseIdentityRef,
			ExpectedCatalogHash: cat.CatalogHash,
		}
		if err := w.WriteConditionCatalog(ctx, art.RootDir, cat, e2eBinding); err != nil {
			t.Fatalf("WriteConditionCatalog: %v", err)
		}
		if err := w.WriteDecision(ctx, outDir, pkg); err != nil {
			t.Fatalf("WriteDecision: %v", err)
		}
		t.Logf("stage0.json: %s", mustReadFile(t, filepath.Join(art.RootDir, "stage0.json")))
		rep, err := triage.PrepareReplay(ctx, art.RootDir)
		if err != nil {
			t.Fatalf("PrepareReplay: %v", err)
		}
		if rep.Decision == nil {
			t.Fatal("replay did not recompose the decision")
		}
		// --- universal verification pass over the run's claims ---
		ex, err := claimshape.ExtractRun(art.RootDir, "")
		if err != nil {
			t.Fatalf("ExtractRun: %v", err)
		}
		if len(ex.Claims) == 0 {
			t.Fatal("no canonical claims extracted")
		}
		archive, err := triage.ReadObservationArchive(filepath.Join(art.RootDir, "observation-archive.json"))
		if err != nil {
			t.Fatalf("archive: %v", err)
		}
		var fr triage.FalsifierReport
		if err := json.Unmarshal(mustReadFile(t, filepath.Join(art.RootDir, "falsifier-verification.json")), &fr); err != nil {
			t.Fatalf("falsifier report: %v", err)
		}
		vrep := verify.Evaluate(verify.Input{
			RunID: rep.SourceRunID, FindingID: in.Finding.FindingID,
			Claims: ex.Claims, Observations: archive.Observations,
			Advisory: ex.Advisory, Falsifiers: &fr,
			SnapshotHash: manifest.ContentHash,
		})
		if vrep.SchemaVersion == "" || len(vrep.Claims) == 0 {
			t.Fatalf("verify report empty: %+v", vrep)
		}
	}
}

// TestE2ENegativeChain: malformed/partial/foreign input can never become a
// reduction — every failure class terminates on its own channel.
func TestE2ENegativeChain(t *testing.T) {
	ctx := context.Background()

	// malformed: authority fields smuggled into a proposal fail at decode.
	bad := `{"schema_version":"`+triage.AssessmentSchemaVersion+`","finding_id":"e2e-001","verdict":"NOT_EXPLOITABLE",` +
		`"falsifier_proposals":[{"id":"fp","claim_id":"c","condition_id":"c1","kind":"code_absent",` +
		`"subjects":[{"package":"p","symbol":"s"}],"verified":true}]}`
	if _, err := triage.DecodeAssessment(bad, "e2e-001"); err == nil {
		t.Fatal("proposal with forbidden authority field decoded")
	}

	// foreign: an obs:/det: locator naming another run's observation id
	// stays UNAVAILABLE — never VALID.
	foreign := triage.Assessment{
		SchemaVersion: triage.AssessmentSchemaVersion,
		FindingID:     "e2e-001",
		Verdict:       triage.VerdictNotExploitable,
		Claims:        []triage.Claim{{ID: "c1", Statement: "x", DecisionRelevant: true, EvidenceRefs: []string{"ev-9"}}},
		Evidence:      []triage.EvidenceRef{{ID: "ev-9", Kind: "det", Locator: "det:foreign-999"}},
	}
	fv := triage.FactGate{}.Validate(ctx, triage.FindingInput{}, triage.SnapshotManifest{}, foreign)
	if fv.Status == triage.ValidationComplete {
		t.Fatalf("foreign observation locator validated: %+v", fv)
	}
	var ref *triage.ReferenceCheck
	for i := range fv.References {
		if fv.References[i].EvidenceID == "ev-9" {
			ref = &fv.References[i]
		}
	}
	if ref == nil || ref.Status != triage.FactUnavailable {
		t.Fatalf("foreign det: reference = %+v, want UNAVAILABLE", ref)
	}

	// partial: an unstable run cannot lower or dismiss — the composer
	// demotes to UNCHANGED — while provenance drift must stay on the
	// technical-error channel. The fixture keeps production-shaped Stage 0
	// material (pinned snapshot, captured advisory record), so the drift
	// refusal is exercised instead of the missing-input action restriction.
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "e2e-product"))
	if err != nil {
		t.Fatal(err)
	}
	fin := triage.FindingInput{Finding: triage.Finding{
		SchemaVersion: triage.FindingSchemaVersion, FindingID: "e2e-001",
		Vulnerability: triage.Vulnerability{IDs: []string{"CVE-2099-0001"}},
		Component:     triage.Component{Package: "example.com/sessiondep", Version: "v0.5.0"},
		Target:        triage.Target{Repository: repoRoot},
		Scanner:       triage.Scanner{Severity: "high"},
	}}
	rawFinding, err := json.Marshal(fin.Finding)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := triage.ParseFindings(strings.NewReader(string(rawFinding)))
	if err != nil || len(parsed) != 1 {
		t.Fatalf("ParseFindings: %v (n=%d)", err, len(parsed))
	}
	fin = parsed[0]
	manifest, err := (triage.LocalSnapshotBuilder{Now: e2eClock}).Build(ctx, fin)
	if err != nil {
		t.Fatalf("snapshot build: %v", err)
	}
	s0 := e2eStage0(t, fin, manifest, manifest.ContentHash)
	a := triage.Assessment{
		SchemaVersion: triage.AssessmentSchemaVersion,
		FindingID:     "e2e-001",
		Verdict:       triage.VerdictNotExploitable,
		Claims: []triage.Claim{{
			ID:               "c1",
			Statement:        "the vulnerable component is not reachable from the captured entry point",
			Basis:            triage.PremiseInterpreted,
			Subject:          "reachability",
			Scope:            "captured snapshot",
			DecisionRelevant: true,
		}},
		ProposedAction: triage.HumanAction{
			Kind:             triage.HumanActionClose,
			Instruction:      "close the ticket as not exploitable",
			Rationale:        "the decisive claim is an interpretation of the captured snapshot",
			Scope:            "captured snapshot",
			DecisiveClaimIDs: []string{"c1"},
			ReconsiderWhen:   []string{"a reachable call path is captured"},
		},
	}
	pkg, err := triage.Composer{Stability: &triage.StabilityReport{Retries: 2, Stable: false}}.
		Compose(ctx, s0, a, triage.FactValidation{Status: triage.ValidationComplete}, nil)
	if err != nil {
		t.Fatalf("compose with unstable stability: %v", err)
	}
	if rec := pkg.MachineDisposition.Recommendation; rec == triage.RecommendationDismissed || rec == triage.RecommendationLowered {
		t.Fatalf("unstable run yielded a reduction: %s", rec)
	}
	_, err = (triage.Composer{Stability: &triage.StabilityReport{
		Retries: 2, Drift: true,
		Limitations: []string{"fixture provenance drift between attempts"},
	}}).Compose(ctx, s0, a, triage.FactValidation{Status: triage.ValidationComplete}, nil)
	if err == nil {
		t.Fatal("provenance drift produced a decision package")
	}
	if !strings.Contains(err.Error(), "provenance drift") {
		t.Fatalf("provenance drift did not land on its refusal channel: %v", err)
	}
}

// strconv renders a JSON string literal for the target repository.
func strconv(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

package triage

// Phase 1 human-result acceptance matrix. Each case exercises the real
// agent runner over a local snapshot, the real fact gate, the real trusted
// composer, the real support derivation and the real artifact/human-review
// surfaces. Only the model's chat replies are scripted.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/llm"
	"github.com/davniy/izyan/internal/productb/vulnerability"
)

const humanResultFindingID = "human-result-001"

// humanResultInput builds one finding against a source tree the real
// snapshot builder can pin.
func humanResultInput(t *testing.T) (FindingInput, SnapshotManifest) {
	t.Helper()
	repo := newReplayRepo(t)
	raw, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     humanResultFindingID,
		Vulnerability: Vulnerability{IDs: []string{"CVE-2099-0001"}},
		Component:     Component{Name: "service-example", Package: "example.org/library", Version: "v1.2.3"},
		Target:        Target{Repository: repo},
		Scanner:       Scanner{Severity: "high"},
	})
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	findings, err := ParseFindings(strings.NewReader(string(raw)))
	if err != nil || len(findings) != 1 {
		t.Fatalf("ParseFindings: %v (n=%d)", err, len(findings))
	}
	manifest, err := (LocalSnapshotBuilder{Now: replayClockA}).Build(context.Background(), findings[0])
	if err != nil {
		t.Fatalf("snapshot build: %v", err)
	}
	return findings[0], manifest
}

// humanResultStage0 binds the resolved Stage 0 fixture to the live finding
// and its pinned snapshot: confirmed intake, a frozen advisory record with a
// digest, a matched package check and a pinned source snapshot.
func humanResultStage0(t *testing.T, in FindingInput, manifest SnapshotManifest) Stage0Result {
	t.Helper()
	s0 := goodStage0()
	s0.Input = in
	s0.Snapshot = manifest
	s0.Raw = RawIntake{Raw: in.Raw, TicketHash: in.SHA256, Format: IntakeJSON}
	s0.Source = MaterializedSource{
		Root: in.Finding.Target.Repository,
		Metadata: MaterializationMetadata{
			Mode: MaterializationLocal, SourceID: "service-example",
			SelectedRef: "v1.4.0", ResolvedCommit: manifest.ResolvedRevision,
			RootHash: manifest.ContentHash, CreatedAt: "2026-10-16T00:00:00Z",
		},
	}
	s0.Proposal.VulnerabilityIDs = []string{"CVE-2099-0001"}
	s0.Proposal.Package = "example.org/library"
	s0.Proposal.Version = "v1.2.3"
	s0.Proposal.Severity = "high"
	for i := range s0.Validation.Fields {
		if s0.Validation.Fields[i].Field == "vulnerability_ids" {
			s0.Validation.Fields[i].Value = "CVE-2099-0001"
		}
	}
	s0.Advisory.ID = "CVE-2099-0001"
	s0.Advisory.ResolvedID = "CVE-2099-0001"
	s0.Resolution.Record = s0.Advisory
	s0.Resolution.Vulnerability.ID = "CVE-2099-0001"
	return s0
}

// humanResultRun is one real runner execution plus the deterministic gate
// report it produced.
type humanResultRun struct {
	run AgentRun
	fv  FactValidation
}

// humanResultReplies turns one scripted assessment into the model's final
// reply, after any scripted tool-call turns.
func humanResultReplies(t *testing.T, a Assessment, toolTurns ...llm.ChatMessage) []llm.ChatMessage {
	t.Helper()
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal assessment: %v", err)
	}
	return append(toolTurns, llm.ChatMessage{Role: "assistant", Content: string(data)})
}

// runHumanResultAgent runs the real bounded agent loop and fact gate over
// the finding's own snapshot. No network and no real model are involved.
func runHumanResultAgent(t *testing.T, s0 Stage0Result, in FindingInput, manifest SnapshotManifest, replies []llm.ChatMessage, maxSteps int) humanResultRun {
	t.Helper()
	agentIn := Stage0AgentFinding(in, s0.AdvisoryVulnerability())
	tools := &ReadOnlyTools{
		Snapshot:         manifest,
		Finding:          agentIn,
		Advisory:         s0.AdvisoryProjection(),
		ObservationStore: NewRunObservationStore(AttemptRunID(in.Finding.FindingID, 1), 1),
	}
	chat := &scriptedChat{responses: replies}
	run, fv, err := (AgentRunner{
		Client: chat,
		Tools:  tools,
		Limits: AgentLimits{MaxSteps: maxSteps, MaxToolCalls: 8, MaxSourceBytes: 1 << 20},
	}).RunWithFactGate(context.Background(), agentIn, manifest, FactGate{}, 0)
	if err != nil {
		t.Fatalf("agent run: %v", err)
	}
	return humanResultRun{run: run, fv: fv}
}

// composeHumanResult composes the human package from the real run output,
// exactly as the live driver does: the gate's status/detail are stamped on
// the assessment and the selected attempt's observations travel as evidence.
func composeHumanResult(t *testing.T, s0 Stage0Result, rt humanResultRun, extra EvidenceInput) DecisionPackage {
	t.Helper()
	a := rt.run.Assessment
	a.FactValidation = rt.fv.Status
	a.FactValidationDetail = &rt.fv
	extra.Observations = rt.run.Observations
	extra.SelectedAttempt = 1
	pkg, err := (Composer{
		RunID:         "human-result-run",
		ExecutionMode: "single",
		RulesetHash:   "human-result-ruleset",
		BudgetResult:  rt.run.BudgetResult(),
	}).ComposeWithEvidence(context.Background(), s0, a, rt.fv, extra)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if err := pkg.Validate(); err != nil {
		t.Fatalf("composed package invalid: %v", err)
	}
	return pkg
}

func humanResultPremise(t *testing.T, pkg DecisionPackage, id string) DecisionPremise {
	t.Helper()
	for _, pr := range pkg.Premises {
		if pr.ClaimID == id {
			return pr
		}
	}
	t.Fatalf("premise %q not in %+v", id, pkg.Premises)
	return DecisionPremise{}
}

// TestTriageHumanResultAcceptanceMatrix is the Phase 1 acceptance matrix.
// It asserts observable package fields and the rendered human card for
// every acceptance row; a technical failure is expected to stay on the
// error channel, never to be fabricated into a completed investigation.
func TestTriageHumanResultAcceptanceMatrix(t *testing.T) {
	t.Run("unsupported mechanism without a falsifier kind", func(t *testing.T) {
		in, manifest := humanResultInput(t)
		s0 := humanResultStage0(t, in, manifest)
		a := Assessment{
			SchemaVersion: AssessmentSchemaVersion,
			FindingID:     humanResultFindingID,
			Verdict:       VerdictNotExploitable,
			Summary:       "the vulnerable parser is never invoked by the captured entry points",
			Mechanism:     "the only parser references sit behind a build tag the release binary does not set",
			Claims: []Claim{{
				ID:               "c1",
				Statement:        "the captured build contains no call into the vulnerable parser",
				Basis:            PremiseInterpreted,
				Subject:          "call-path reachability",
				Scope:            "captured snapshot",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"ev-1"},
				Binding:          &PremiseBinding{Kind: BindingQuotedText, ReferenceID: "ev-1"},
			}},
			Evidence:       []EvidenceRef{{ID: "ev-1", Kind: "source_span", Locator: "main.go:1-2", Quote: "line 1"}},
			ProposedAction: closeAction("c1"),
		}
		rt := runHumanResultAgent(t, s0, in, manifest, humanResultReplies(t, a), 4)
		pkg := composeHumanResult(t, s0, rt, EvidenceInput{})

		if pkg.Judgment.Verdict != a.Verdict || pkg.Judgment.Summary != a.Summary || pkg.Judgment.Mechanism != a.Mechanism {
			t.Fatalf("model judgment was rewritten: %+v", pkg.Judgment)
		}
		if pkg.ProposedAction.Kind != a.ProposedAction.Kind || pkg.ProposedAction.Instruction != a.ProposedAction.Instruction {
			t.Fatalf("proposed action was rewritten: %+v", pkg.ProposedAction)
		}
		pr := humanResultPremise(t, pkg, "c1")
		if pr.Basis != PremiseInterpreted || pr.Statement != a.Claims[0].Statement {
			t.Fatalf("interpreted premise not visible: %+v", pr)
		}
		if pkg.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED for an interpretation-only graph (%v)", pkg.Support.Level, pkg.Support.Reasons)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("machine disposition = %s, want UNCHANGED", pkg.MachineDisposition.Recommendation)
		}
		if len(pkg.FalsifierProofs) != 0 {
			t.Fatalf("unsupported mechanism produced proofs: %+v", pkg.FalsifierProofs)
		}
		if card := string(RenderDecisionMarkdown(pkg)); !strings.Contains(card, "INTERPRETED") ||
			!strings.Contains(card, a.Mechanism) || !strings.Contains(card, "## Accept or reject this proposal (human decision)") {
			t.Fatalf("card does not expose the interpretation and the human review surface:\n%s", card)
		}
	})

	t.Run("exact captured advisory without a corpus declaration", func(t *testing.T) {
		in, manifest := humanResultInput(t)
		s0 := humanResultStage0(t, in, manifest)
		a := Assessment{
			SchemaVersion: AssessmentSchemaVersion,
			FindingID:     humanResultFindingID,
			Verdict:       VerdictNotExploitable,
			Summary:       "the declared vulnerable file is absent from the captured build",
			Claims: []Claim{{
				ID:               "c1",
				Statement:        "the captured build does not contain the parser source the advisory describes",
				Basis:            PremiseInterpreted,
				Subject:          "vulnerable parser source",
				Scope:            "captured snapshot",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"ev-1"},
				Binding:          &PremiseBinding{Kind: BindingQuotedText, ReferenceID: "ev-1"},
			}},
			Evidence:       []EvidenceRef{{ID: "ev-1", Kind: "source_span", Locator: "main.go:1-2", Quote: "line 1"}},
			ProposedAction: closeAction("c1"),
		}
		rt := runHumanResultAgent(t, s0, in, manifest, humanResultReplies(t, a), 4)
		pkg := composeHumanResult(t, s0, rt, EvidenceInput{})

		if pkg.Scope.Boundary != DecisionBoundaryExactRecords {
			t.Fatalf("scope boundary = %q, want %q", pkg.Scope.Boundary, DecisionBoundaryExactRecords)
		}
		if len(pkg.Scope.Records) != 1 || pkg.Scope.Records[0].ID != "CVE-2099-0001" ||
			pkg.Scope.Records[0].SHA256 != s0.Advisory.SHA256 {
			t.Fatalf("scope records = %+v, want the captured advisory record and digest", pkg.Scope.Records)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("record-bound conclusion produced machine %s", pkg.MachineDisposition.Recommendation)
		}
		card := string(RenderDecisionMarkdown(pkg))
		for _, want := range []string{
			"## Decision scope", "EXACT_RECORDS", "CVE-2099-0001", s0.Advisory.SHA256, "no CVE-wide statement",
		} {
			if !strings.Contains(card, want) {
				t.Fatalf("card lacks scope evidence %q:\n%s", want, card)
			}
		}
		if strings.Contains(card, "NOT_AFFECTED") || strings.Contains(card, "NO_EXPLOIT_PATH_FOUND") {
			t.Fatalf("record-bound conclusion presented as a CVE-wide safe claim:\n%s", card)
		}
	})

	t.Run("partial or unsupported relevant tool", func(t *testing.T) {
		in, manifest := humanResultInput(t)
		s0 := humanResultStage0(t, in, manifest)
		a := Assessment{
			SchemaVersion: AssessmentSchemaVersion,
			FindingID:     humanResultFindingID,
			Verdict:       VerdictInconclusive,
			Summary:       "the dependency graph tool is not available in this build",
			Claims: []Claim{{
				ID:               "c1",
				Statement:        "the module is absent from the recorded build graph",
				Basis:            PremiseMeasured,
				Subject:          "example.org/library build-graph membership",
				Scope:            "recorded build graph",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"ev-1"},
				Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-1"},
			}},
			Evidence: []EvidenceRef{{ID: "ev-1", Kind: "observation", Locator: "obs:obs-0001"}},
			ProposedAction: HumanAction{
				Kind:             HumanActionObtainEvidence,
				Instruction:      "capture a complete module graph with go list -m all",
				Rationale:        "the attempted module-graph tool is unsupported in this build, so absence was not established",
				Scope:            "the captured product build",
				DecisiveClaimIDs: []string{"c1"},
				ReconsiderWhen:   []string{"a complete module graph is captured"},
			},
		}
		tool := llm.ChatMessage{Role: "assistant", ToolCalls: []llm.ToolCall{{
			ID: "call-1", Type: "function",
			Function: llm.FunctionCall{Name: "go_list", Arguments: "{}"},
		}}}
		rt := runHumanResultAgent(t, s0, in, manifest, humanResultReplies(t, a, tool), 4)
		if rt.fv.Status == ValidationComplete {
			t.Fatalf("unsupported tool produced a complete fact gate: %+v", rt.fv)
		}
		pkg := composeHumanResult(t, s0, rt, EvidenceInput{})

		pr := humanResultPremise(t, pkg, "c1")
		if pr.Basis != PremiseUnresolved {
			t.Fatalf("unsupported observation premise basis = %s, want UNRESOLVED", pr.Basis)
		}
		if !hasSupportReason(pr.Reasons, "UNSUPPORTED") {
			t.Fatalf("support reason does not name the unsupported tool: %v", pr.Reasons)
		}
		if pkg.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED (%v)", pkg.Support.Level, pkg.Support.Reasons)
		}
		if pkg.ProposedAction.Kind != HumanActionObtainEvidence {
			t.Fatalf("human action was not delivered: %+v", pkg.ProposedAction)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("unsupported tool produced machine %s", pkg.MachineDisposition.Recommendation)
		}
		if hasFact(pkg.Facts, FactFalsifierAdmitted, ObsSupports) {
			t.Fatalf("unsupported tool fabricated an admitted absence fact: %+v", pkg.Facts)
		}
		if !hasLimitationContaining(pkg.TechnicalAssessment.Limitations, "UNAVAILABLE") {
			t.Fatalf("scoped limitation missing from the package: %v", pkg.TechnicalAssessment.Limitations)
		}
	})

	t.Run("no severity and no configured default", func(t *testing.T) {
		in, manifest := humanResultInput(t)
		s0 := humanResultStage0(t, in, manifest)
		s0.Resolution.Vulnerability.BaseSeverity = ""
		s0.Resolution.Vulnerability.BaseScore = 0
		s0.Proposal.Severity = ""
		s0.Input.Finding.Scanner.Severity = ""
		for i := range s0.Validation.Fields {
			if s0.Validation.Fields[i].Field == "severity" {
				s0.Validation.Fields[i].Status = IntakeUnavailable
				s0.Validation.Fields[i].Value = ""
				s0.Validation.Fields[i].Provenance = nil
			}
		}
		a := humanOnlyAssessment()
		a.FindingID = humanResultFindingID
		a.Audit = nil
		rt := runHumanResultAgent(t, s0, in, manifest, humanResultReplies(t, a), 4)
		pkg := composeHumanResult(t, s0, rt, EvidenceInput{})

		if pkg.MachineDisposition.Baseline != nil {
			t.Fatalf("absent severity invented a baseline: %+v", pkg.MachineDisposition.Baseline)
		}
		data, err := json.Marshal(pkg)
		if err != nil {
			t.Fatalf("marshal package: %v", err)
		}
		var wire struct {
			MachineDisposition map[string]any `json:"machine_disposition"`
		}
		if err := json.Unmarshal(data, &wire); err != nil {
			t.Fatalf("unmarshal package: %v", err)
		}
		for _, key := range []string{"baseline", "severity", "priority"} {
			if _, ok := wire.MachineDisposition[key]; ok {
				t.Fatalf("machine disposition invented %q: %v", key, wire.MachineDisposition)
			}
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("no baseline produced machine %s", pkg.MachineDisposition.Recommendation)
		}
		if !hasLimitationContaining(pkg.TechnicalAssessment.Limitations, "no authoritative severity baseline") {
			t.Fatalf("absent baseline is not recorded: %v", pkg.TechnicalAssessment.Limitations)
		}
		if pkg.ProposedAction.Kind != HumanActionClose || pkg.Judgment.Verdict != VerdictNotExploitable {
			t.Fatalf("missing severity damaged the human result: %+v / %+v", pkg.Judgment, pkg.ProposedAction)
		}
	})

	t.Run("no external baseline", func(t *testing.T) {
		f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
		rep, err := PrepareReplay(context.Background(), f.runDir)
		if err != nil {
			t.Fatalf("replay without an external control: %v", err)
		}
		if rep.Decision == nil {
			t.Fatal("replay did not deliver the recorded human package")
		}
		if rep.Decision.MachineDisposition.Baseline == nil {
			t.Fatalf("fixture lost its authoritative severity baseline")
		}
		if rep.Decision.ProposedAction.Instruction == "" || rep.Decision.Judgment.Verdict == "" {
			t.Fatalf("replayed package lacks the human axes: %+v", rep.Decision)
		}
		// The only thresholds are the explicitly named policy ones; no
		// control result is part of the package or its replay.
		_ = PackagePolicyHit(*rep.Decision, FailOnUnchanged)
	})

	t.Run("missing necessary identity and material", func(t *testing.T) {
		in, manifest := humanResultInput(t)
		s0 := humanResultStage0(t, in, manifest)
		s0.Advisory = vulnerability.FrozenAdvisory{}
		s0.Resolution = nil
		a := Assessment{
			SchemaVersion: AssessmentSchemaVersion,
			FindingID:     humanResultFindingID,
			Verdict:       VerdictInconclusive,
			Summary:       "the advisory record was not captured",
			Claims: []Claim{{
				ID:               "c1",
				Statement:        "the exact advisory document for CVE-2099-0001 has not been captured",
				Basis:            PremiseUnresolved,
				Subject:          "advisory identity and material",
				Scope:            "recorded input",
				DecisionRelevant: true,
				Reason:           "no frozen advisory record with a digest is present",
			}},
			ProposedAction: HumanAction{
				Kind:             HumanActionObtainEvidence,
				Instruction:      "capture the exact advisory document for CVE-2099-0001 and its sha256 digest",
				Rationale:        "without the exact record no record-scoped conclusion can be established",
				Scope:            "the recorded input",
				DecisiveClaimIDs: []string{"c1"},
				ReconsiderWhen:   []string{"the exact advisory record and digest are captured"},
			},
		}
		rt := runHumanResultAgent(t, s0, in, manifest, humanResultReplies(t, a), 4)
		pkg := composeHumanResult(t, s0, rt, EvidenceInput{})

		if pkg.Support.Level != SupportLevelInsufficient {
			t.Fatalf("support = %s, want INSUFFICIENT (%v)", pkg.Support.Level, pkg.Support.Reasons)
		}
		if !hasSupportReason(pkg.Support.Reasons, "no advisory material") ||
			!hasSupportReason(pkg.Support.Reasons, "OBTAIN_EVIDENCE") {
			t.Fatalf("missing input and its consequence are not named: %v", pkg.Support.Reasons)
		}
		if pkg.ProposedAction.Kind != HumanActionObtainEvidence {
			t.Fatalf("missing material action = %s", pkg.ProposedAction.Kind)
		}
		if !hasSupportReason([]string{pkg.ProposedAction.Instruction}, "advisory document") ||
			!hasSupportReason([]string{pkg.ProposedAction.Rationale}, "record-scoped") {
			t.Fatalf("action does not name the exact missing input and consequence: %+v", pkg.ProposedAction)
		}
		if pkg.Scope.Boundary != DecisionBoundaryInputMaterialOnly || len(pkg.Scope.Records) != 0 {
			t.Fatalf("missing material invented a scope: %+v", pkg.Scope)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("missing material produced machine %s", pkg.MachineDisposition.Recommendation)
		}
	})

	t.Run("existing admitted proof", func(t *testing.T) {
		s0 := observedStage0()
		proposal, report := supportProof(t, s0, "c1")
		observation := supportObservation(t, s0, "obs-1", "package example.org/library is absent", 1)
		// The claim must express the certificate's own narrow proposition;
		// the action must name the captured record and prove within the
		// certificate's scope.
		claim := proofClaim(t, "c1", report)
		assessment := supportAssessment(
			[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
			[]Claim{claim}, nil, "c1",
		)
		assessment.ProposedAction.RecordIDs = []string{"CVE-2099-0001"}
		assessment.ProposedAction.Scope = claim.Scope
		assessment.Verdict = VerdictNotExploitable
		assessment.Summary = "the vulnerable package is absent from the recorded build graph"
		assessment.FalsifierProposals = []FalsifierProposal{proposal}
		validation := supportValidation(s0.Snapshot.ContentHash, "ev-1")
		pkg, err := (Composer{
			RunID: "human-result-proof-run", ExecutionMode: "single", RulesetHash: "human-result-ruleset",
		}).ComposeWithEvidence(context.Background(), s0, assessment, validation, EvidenceInput{
			Observations:    []RecordedObservation{observation},
			Falsifiers:      &report,
			SelectedAttempt: 1,
		})
		if err != nil {
			t.Fatalf("compose admitted proof: %v", err)
		}
		if pkg.Support.Level != SupportLevelProvedWithinScope {
			t.Fatalf("support = %s, want PROVED_WITHIN_SCOPE (%v)", pkg.Support.Level, pkg.Support.Reasons)
		}
		if len(pkg.FalsifierProofs) != 1 || pkg.FalsifierProofs[0].ID != "fp-1" ||
			pkg.FalsifierProofs[0].Status != FalsifierVerified {
			t.Fatalf("admitted proof not carried: %+v", pkg.FalsifierProofs)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationDismissed ||
			pkg.MachineDisposition.Automation != AutomationAllow {
			t.Fatalf("admitted proof did not preserve the scoped machine reduction: %+v", pkg.MachineDisposition)
		}
		if pkg.Audit.FalsifierHash != report.Hash {
			t.Fatalf("falsifier hash = %q, want report hash %q", pkg.Audit.FalsifierHash, report.Hash)
		}
		proof := pkg.FalsifierProofs[0]
		if proof.Coverage.SnapshotHash != s0.Snapshot.ContentHash ||
			proof.Coverage.BuildContextHash == "" ||
			!sameSubjects(proof.Coverage.ExpectedSubjects, proof.Coverage.CheckedSubjects) {
			t.Fatalf("proof bindings are not reconstructable: %+v", proof.Coverage)
		}
		if violations := ValidateProofCertificate(proof, map[string]FalsifierProposal{"fp-1": proposal}, s0.Snapshot.ContentHash); len(violations) > 0 {
			t.Fatalf("recorded proof does not re-validate: %+v", violations)
		}
	})

	t.Run("forged or foreign proof and identity drift", func(t *testing.T) {
		s0 := observedStage0()
		proposal, report := supportProof(t, s0, "c1")
		claim := Claim{
			ID:               "c1",
			Statement:        "example.org/library is absent from the residual build graph",
			Basis:            PremiseProved,
			Subject:          "example.org/library absence",
			Scope:            "snapshot",
			DecisionRelevant: true,
			EvidenceRefs:     []string{"ev-1"},
			Binding:          &PremiseBinding{Kind: BindingFalsifierProof, ReferenceID: "fp-1"},
		}
		assessment := supportAssessment(
			[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
			[]Claim{claim}, nil, "c1",
		)
		assessment.FalsifierProposals = []FalsifierProposal{proposal}
		validation := supportValidation(s0.Snapshot.ContentHash, "ev-1")
		observation := supportObservation(t, s0, "obs-1", "package example.org/library is absent", 1)

		// A self-consistent report whose certificate binds a foreign
		// snapshot is malformed material: composition must fail closed.
		forged := report
		forged.Proofs = append([]FalsifierProof(nil), report.Proofs...)
		forged.Proofs[0].Coverage.SnapshotHash = strings.Repeat("ff", 32)
		forged = NewFalsifierReport(forged.RuleSetHash, forged.Proofs...)
		if _, err := (Composer{}).ComposeWithEvidence(context.Background(), s0, assessment, validation, EvidenceInput{
			Observations:    []RecordedObservation{observation},
			Falsifiers:      &forged,
			SelectedAttempt: 1,
		}); err == nil {
			t.Fatal("forged proof was accepted")
		} else if !strings.Contains(err.Error(), "fp-1") {
			t.Fatalf("forged-proof diagnostics do not name the proof: %v", err)
		}

		// Identity drift between the intake finding and the assessment is a
		// technical error, not a different human result.
		drifted := assessment
		drifted.FindingID = "other-finding"
		if _, err := (Composer{}).ComposeWithEvidence(context.Background(), s0, drifted, validation, EvidenceInput{
			Observations:    []RecordedObservation{observation},
			Falsifiers:      &report,
			SelectedAttempt: 1,
		}); err == nil {
			t.Fatal("identity drift produced a decision package")
		} else if !strings.Contains(err.Error(), "finding-example-001") || !strings.Contains(err.Error(), "other-finding") {
			t.Fatalf("identity-drift diagnostics are not preserved: %v", err)
		}
	})

	t.Run("semantic stability disagreement", func(t *testing.T) {
		primaryAssessment := humanOnlyAssessment()
		primary := composeOrFail(t, undecidedStage0(), primaryAssessment, completeValidation())

		otherAssessment := primaryAssessment
		otherAssessment.Verdict = VerdictInconclusive
		otherAssessment.Summary = "the captured material does not decide reachability"
		other := composeOrFail(t, undecidedStage0(), otherAssessment, completeValidation())

		attempts := []StabilityAttempt{
			ProjectStabilityAttempt(1, primary),
			ProjectStabilityAttempt(2, other),
		}
		report := CheckStability(attempts)
		if report.Stable || report.Drift {
			t.Fatalf("stability report = stable=%v drift=%v, want semantic disagreement", report.Stable, report.Drift)
		}
		if !hasSupportReason(report.Limitations, "judgment") {
			t.Fatalf("stability disagreement is not recorded: %v", report.Limitations)
		}
		pkg, err := (Composer{Stability: &report}).ComposeWithEvidence(
			context.Background(), undecidedStage0(), primaryAssessment, completeValidation(), EvidenceInput{})
		if err != nil {
			t.Fatalf("compose unstable run: %v", err)
		}
		if pkg.TechnicalAssessment.StabilityResult != "unstable" {
			t.Fatalf("stability result = %q, want the recorded semantic disagreement", pkg.TechnicalAssessment.StabilityResult)
		}
		if pkg.Support.Level != SupportLevelLimited || !hasSupportReason(pkg.Support.Reasons, "stability") {
			t.Fatalf("unstable support = %s (%v), want LIMITED naming stability", pkg.Support.Level, pkg.Support.Reasons)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("unstable run produced machine %s", pkg.MachineDisposition.Recommendation)
		}
	})

	t.Run("budgeted investigation with valid finalization", func(t *testing.T) {
		in, manifest := humanResultInput(t)
		s0 := humanResultStage0(t, in, manifest)
		a := Assessment{
			SchemaVersion: AssessmentSchemaVersion,
			FindingID:     humanResultFindingID,
			Verdict:       VerdictInconclusive,
			Summary:       "only the first captured file was inspected before the exchange budget ended",
			Claims: []Claim{{
				ID:               "c1",
				Statement:        "the captured entry point does not mention the vulnerable parser",
				Basis:            PremiseInterpreted,
				Subject:          "entry-point call path",
				Scope:            "captured snapshot",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"ev-1"},
				Binding:          &PremiseBinding{Kind: BindingQuotedText, ReferenceID: "ev-1"},
			}},
			Evidence: []EvidenceRef{{ID: "ev-1", Kind: "source_span", Locator: "main.go:1-2", Quote: "line 1"}},
			ProposedAction: HumanAction{
				Kind:             HumanActionKeepOpen,
				Instruction:      "keep the ticket open and finish the call-path review",
				Rationale:        "the captured first lines do not decide whether the vulnerable parser is invoked",
				Scope:            "the captured entry point",
				DecisiveClaimIDs: []string{"c1"},
				ReconsiderWhen:   []string{"the remaining call paths are inspected"},
			},
		}
		tool := llm.ChatMessage{Role: "assistant", ToolCalls: []llm.ToolCall{{
			ID: "call-1", Type: "function",
			Function: llm.FunctionCall{Name: "read_file", Arguments: `{"path":"main.go"}`},
		}}}
		rt := runHumanResultAgent(t, s0, in, manifest, humanResultReplies(t, a, tool), 1)
		if !rt.run.Finalized || rt.run.Steps != 2 {
			t.Fatalf("run did not finalize after the step budget: finalized=%v steps=%d", rt.run.Finalized, rt.run.Steps)
		}
		if rt.run.BudgetResult() != "finalized_after_step_budget" {
			t.Fatalf("budget result = %q", rt.run.BudgetResult())
		}
		pkg := composeHumanResult(t, s0, rt, EvidenceInput{})
		if pkg.TechnicalAssessment.BudgetResult != "finalized_after_step_budget" {
			t.Fatalf("package budget result = %q", pkg.TechnicalAssessment.BudgetResult)
		}
		pr := humanResultPremise(t, pkg, "c1")
		if len(pr.SourceRefs) == 0 || !hasSupportReason(pr.SourceRefs, "main.go") {
			t.Fatalf("finalized premise does not cite the collected material: %+v", pr)
		}
		if pkg.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED for the collected-material-only action (%v)", pkg.Support.Level, pkg.Support.Reasons)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("budgeted finalization produced machine %s", pkg.MachineDisposition.Recommendation)
		}
		card := string(RenderDecisionMarkdown(pkg))
		if !strings.Contains(card, "finalized_after_step_budget") {
			t.Fatalf("card hides the budget outcome:\n%s", card)
		}
		if strings.Contains(strings.ToLower(card), "investigation complete") {
			t.Fatalf("card claims the budgeted investigation was complete:\n%s", card)
		}
	})
}

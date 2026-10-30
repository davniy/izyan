package triage

import (
	"context"
	"encoding/json"
	"github.com/davniy/izyan/internal/evidencetools"
	"path/filepath"
	"strings"
	"testing"
)

// v3ProofReport builds a verifier report bound to the fixture snapshot and
// to the proposal the fixture assessment declares.
func v3ProofReport(snap string) FalsifierReport {
	r := FalsifierReport{
		SchemaVersion: FalsifierVerificationSchemaVersion,
		RuleSetHash:   strings.Repeat("07", 32),
		Proofs: []FalsifierProof{{
			ID:          "fp-1",
			ProposalID:  "fp-1",
			ClaimID:     "c1",
			ConditionID: "cond-1",
			Kind:        FalsifierCodeAbsent,
			Status:      FalsifierVerified,
			Basis:       BasisCheckerVerified,
			Mandatory:   true,
			RuleID:      "rule-1",
			RuleVersion: "v1",
			EvidenceRefs: []string{
				"ev-1",
			},
			Coverage: FalsifierCoverage{
				Scope: "snapshot", Completeness: "COMPLETE", SnapshotHash: snap, BuildContextHash: "build-1", ClosureHash: "closure-hash-1", ClosureComplete: true, CoverageRuleVersion: "4",
				ScopeRule: evidencetools.CodeAbsenceScopeRule, ScopeComplete: true, ScopeHash: "scope-hash-1", ShippingRoots: []string{"cmd/app"}, PackageStates: map[string]string{"cmd/app": "LIVE"}, DynamicRelevanceRule: evidencetools.CodeAbsenceDynamicRule, DynamicRelevanceComplete: true,
				ExpectedSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}, CheckedSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}, AbsentSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}},
			},
			History: []FalsifierTransition{{From: FalsifierUnknown, To: FalsifierVerified, Reason: "deterministic checker verified complete absence"}},
		}},
	}
	bindCurrentCoverageInventory(&r.Proofs[0].Coverage)
	r.Hash = reportHash(r)
	return r
}

// TestDecisionPackageV3ProofContract pins the package-level proof rules: a
// proof-bearing package needs the report hash, and a VERIFIED proof must
// carry its checker basis, mandatory binding, complete scope and bindings.
func TestDecisionPackageV4ProofContract(t *testing.T) {
	if DecisionPackageSchemaVersion != "decision-package.v4" {
		t.Fatalf("schema version = %s", DecisionPackageSchemaVersion)
	}
	base := func() DecisionPackage {
		p := validDecisionPackage()
		p.FindingID = "finding-example-001"
		p.FalsifierProofs = []FalsifierProof{v3ProofReport("snap-1").Proofs[0]}
		p.Audit.FalsifierHash = "hash-1"
		return p
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid proof-bearing package rejected: %v", err)
	}

	cases := map[string]func(p *DecisionPackage){
		"missing report hash": func(p *DecisionPackage) { p.Audit.FalsifierHash = "" },
		"missing identity":    func(p *DecisionPackage) { p.FalsifierProofs[0].ID = "" },
		"non-checker basis":   func(p *DecisionPackage) { p.FalsifierProofs[0].Basis = BasisLLMProposed },
		"not mandatory":       func(p *DecisionPackage) { p.FalsifierProofs[0].Mandatory = false },
		"partial scope":       func(p *DecisionPackage) { p.FalsifierProofs[0].Coverage.Completeness = "PARTIAL" },
		"subject mismatch": func(p *DecisionPackage) {
			p.FalsifierProofs[0].Coverage.ExpectedSubjects = append(p.FalsifierProofs[0].Coverage.ExpectedSubjects,
				FalsifierSubject{Package: "example.org/library", Symbol: "Wrapper"})
		},
		"missing bindings": func(p *DecisionPackage) { p.FalsifierProofs[0].Coverage.BuildContextHash = "" },
		"no evidence":      func(p *DecisionPackage) { p.FalsifierProofs[0].EvidenceRefs = nil },
		"bad history":      func(p *DecisionPackage) { p.FalsifierProofs[0].History[0].From = "" },
	}
	for name, mutate := range cases {
		p := base()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// TestWriteFalsifierReportBindsPackage pins the sidecar contract: the report
// is written atomically, and the package that cites it is verified against
// the persisted content.
func TestWriteFalsifierReportBindsPackage(t *testing.T) {
	ctx := context.Background()
	out := t.TempDir()
	art, _, _ := writeDecisionRun(t, out)
	report := v3ProofReport(mustStage0SnapshotHash(t, art))

	// A report whose hash does not match its content is refused outright.
	tampered := report
	tampered.Proofs = append([]FalsifierProof(nil), report.Proofs...)
	tampered.Proofs[0].Mandatory = false
	if err := (ArtifactWriter{}).WriteFalsifierReport(ctx, art.RootDir, tampered); err == nil {
		t.Fatal("tampered report written")
	}

	if err := (ArtifactWriter{}).WriteFalsifierReport(ctx, art.RootDir, report); err != nil {
		t.Fatalf("WriteFalsifierReport: %v", err)
	}
	if _, err := filepath.Glob(filepath.Join(art.RootDir, "falsifier-verification.json")); err != nil {
		t.Fatal(err)
	}

	pkg := composedPackageWithProofs(t, art, report)
	if err := (ArtifactWriter{}).WriteDecision(ctx, art.RootDir, pkg); err != nil {
		t.Fatalf("WriteDecision with proofs: %v", err)
	}

	// A package citing a report hash with no sidecar never writes.
	missing := pkg
	missing.Audit.FalsifierHash = strings.Repeat("ab", 32)
	if err := (ArtifactWriter{}).WriteDecision(ctx, art.RootDir, missing); err == nil {
		t.Fatal("package without sidecar accepted")
	}

	// A package whose proof list disagrees with the sidecar never writes.
	diverged := pkg
	diverged.FalsifierProofs[0].Status = FalsifierUnknown
	if err := (ArtifactWriter{}).WriteDecision(ctx, art.RootDir, diverged); err == nil {
		t.Fatal("diverging proofs accepted")
	}

	// A proof bound to another snapshot never writes.
	foreign := pkg
	foreign.FalsifierProofs[0].Coverage.SnapshotHash = "other-snapshot"
	if err := (ArtifactWriter{}).WriteDecision(ctx, art.RootDir, foreign); err == nil {
		t.Fatal("foreign-snapshot proof accepted")
	}
}

func mustStage0SnapshotHash(t *testing.T, art RunArtifacts) string {
	t.Helper()
	var identity struct {
		ContentHash string `json:"content_hash"`
	}
	if err := json.Unmarshal(mustRead(t, art.SnapshotPath), &identity); err != nil {
		t.Fatal(err)
	}
	return identity.ContentHash
}

// composedPackageWithProofs recomposes a package over the fixture run with
// the falsifier report attached, so the sidecar binding is exercised end to
// end: the package must carry the report hash and the verified proofs.
func composedPackageWithProofs(t *testing.T, art RunArtifacts, report FalsifierReport) DecisionPackage {
	t.Helper()
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	rawInput := mustRead(t, art.InputPath)
	var finding Finding
	if err := json.Unmarshal(rawInput, &finding); err != nil {
		t.Fatal(err)
	}
	var snapshotIdentity struct {
		ContentHash string `json:"content_hash"`
		InputHash   string `json:"input_hash"`
	}
	if err := json.Unmarshal(mustRead(t, art.SnapshotPath), &snapshotIdentity); err != nil {
		t.Fatal(err)
	}
	s0 := goodStage0()
	s0.Input = FindingInput{Finding: finding, Raw: rawInput, SHA256: hashBytes(rawInput)}
	s0.Snapshot.ContentHash = snapshotIdentity.ContentHash
	s0.Snapshot.InputHash = snapshotIdentity.InputHash
	// The proof answers a declared proposal: support resolves a proof only
	// through the proposal/certificate contract, so the fixture declares the
	// proposal the verifier answered.
	stored.FalsifierProposals = append(stored.FalsifierProposals, declaredProofProposal("fp-1", "c1", "cond-1"))
	pkg, err := Composer{
		RulesetHash: report.RuleSetHash,
		Limits:      BudgetConfig{MaxLLMSteps: 32, MaxToolCalls: 128, MaxSourceBytes: 1 << 20, TimeoutSeconds: 900},
	}.ComposeWithEvidence(context.Background(), s0, stored, *stored.FactValidationDetail, EvidenceInput{Falsifiers: &report})
	if err != nil {
		t.Fatalf("ComposeWithEvidence: %v", err)
	}
	if pkg.Audit.FalsifierHash != report.Hash || len(pkg.FalsifierProofs) != 1 {
		t.Fatalf("package did not carry the report binding: %+v", pkg.Audit)
	}
	return pkg
}

// TestRenderDecisionMarkdownShowsProofs pins the human-readable proof summary.
func TestRenderDecisionMarkdownShowsProofs(t *testing.T) {
	report := v3ProofReport("snap-1")
	pkg := validDecisionPackage()
	pkg.FindingID = "f-1"
	pkg.FalsifierProofs = report.Proofs
	pkg.Audit.FalsifierHash = report.Hash
	md := string(RenderDecisionMarkdown(pkg))
	for _, want := range []string{"## Falsifier proofs", report.Hash, "fp-1", "code_absent", "CHECKER_VERIFIED", "rule-1@v1", "COMPLETE"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown lacks %q:\n%s", want, md)
		}
	}
}

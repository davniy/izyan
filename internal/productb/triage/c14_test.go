package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// c14Input builds the minimal evidence C14 reasons over: one proposal, its
// proof report, the admitted fact the provider would emit, and the package
// snapshot identity.
func c14Input(t *testing.T, report *FalsifierReport, mutate func(in *CheckInput)) CheckInput {
	t.Helper()
	proposal := FalsifierProposal{
		ID: "fp-1", ClaimID: "c1", ConditionID: "cond-1", Kind: FalsifierCodeAbsent,
		Subjects:     []FalsifierSubject{{Package: "example.org/p", Symbol: "Control"}},
		EvidenceRefs: []string{"ev-1"},
	}
	in := CheckInput{
		Stage0:     goodStage0(),
		Assessment: Assessment{FalsifierProposals: []FalsifierProposal{proposal}},
		Validation: completeValidation(),
		Falsifiers: report,
	}
	if report != nil {
		for _, p := range report.Proofs {
			status := ObsUnavailable
			if p.Status == FalsifierVerified && p.Basis == BasisCheckerVerified {
				status = ObsSupports
			}
			f := newFact("falsifier", FactFalsifierAdmitted, status, "admitted", "falsifier", nil)
			f.EvidenceRefs = append([]string(nil), p.EvidenceRefs...)
			in.Facts = append(in.Facts, f)
		}
	}
	if mutate != nil {
		mutate(&in)
	}
	return in
}

func c14Run(t *testing.T, in CheckInput) CheckResult {
	t.Helper()
	return checkFalsifierProof(context.Background(), in)
}

func c14Report(t *testing.T, mutate func(r *FalsifierReport)) *FalsifierReport {
	t.Helper()
	r := falsifierReport(FalsifierVerified, []string{"ev-1"}, "fp-1")
	r.Proofs[0].Coverage = FalsifierCoverage{
		Scope: "snapshot", Completeness: "COMPLETE", SnapshotHash: goodStage0().Snapshot.ContentHash, BuildContextHash: "build-1", ClosureHash: "closure-hash-1", ClosureComplete: true, CoverageRuleVersion: "4",
		ScopeRule: evidencetools.CodeAbsenceScopeRule, ScopeComplete: true, ScopeHash: "scope-hash-1", ShippingRoots: []string{"cmd/app"}, PackageStates: map[string]string{"cmd/app": "LIVE"}, DynamicRelevanceRule: evidencetools.CodeAbsenceDynamicRule, DynamicRelevanceComplete: true,
		ExpectedSubjects: []FalsifierSubject{{Package: "example.org/p", Symbol: "Control"}}, CheckedSubjects: []FalsifierSubject{{Package: "example.org/p", Symbol: "Control"}}, AbsentSubjects: []FalsifierSubject{{Package: "example.org/p", Symbol: "Control"}},
	}
	bindCurrentCoverageInventory(&r.Proofs[0].Coverage)
	r.Proofs[0].History = []FalsifierTransition{{From: FalsifierUnknown, To: FalsifierVerified, Reason: "verified", RuleID: "rule-1", RuleVersion: "v1"}}
	if mutate != nil {
		mutate(r)
	}
	r.Hash = reportHash(*r)
	return r
}

// TestC14VerifiedProofPasses: a coherent verified report passes the gate.
func TestC14VerifiedProofPasses(t *testing.T) {
	r := c14Report(t, nil)
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckPass {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14AdmittedFactWithoutProofFails: a package may never claim admission
// without the persisted proof behind it.
func TestC14AdmittedFactWithoutProofFails(t *testing.T) {
	got := c14Run(t, c14Input(t, nil, func(in *CheckInput) {
		in.Facts = []DecisionFact{{ID: "fact-falsifier-admitted-x", Kind: FactFalsifierAdmitted, Status: ObsSupports, Scope: "falsifier"}}
	}))
	if got.Status != CheckInvalid || !strings.Contains(strings.Join(got.Reasons, "|"), "no falsifier report was persisted") {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14NonCheckerBasisFails: VERIFIED is a checker-only verdict.
func TestC14NonCheckerBasisFails(t *testing.T) {
	r := c14Report(t, func(r *FalsifierReport) { r.Proofs[0].Basis = BasisLLMProposed })
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckInvalid {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14PartialCoverageFails: a partial scope can never be VERIFIED.
func TestC14PartialCoverageFails(t *testing.T) {
	r := c14Report(t, func(r *FalsifierReport) { r.Proofs[0].Coverage.Completeness = "PARTIAL" })
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckInvalid {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14SubjectSetMismatchFails: expected and checked subject sets must agree.
func TestC14SubjectSetMismatchFails(t *testing.T) {
	r := c14Report(t, func(r *FalsifierReport) {
		r.Proofs[0].Coverage.ExpectedSubjects = append(r.Proofs[0].Coverage.ExpectedSubjects,
			FalsifierSubject{Package: "example.org/p", Symbol: "Wrapper"})
	})
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckInvalid {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14InvalidTransitionFails: history must not carry invented transitions.
func TestC14InvalidTransitionFails(t *testing.T) {
	r := c14Report(t, func(r *FalsifierReport) {
		r.Proofs[0].History = []FalsifierTransition{{From: "", To: FalsifierVerified, Reason: "verified"}}
	})
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckInvalid {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14UnsupportedProposalIsLimitation: an unsupported proof is a boundary,
// not a technical failure — the finding simply stays conservative.
func TestC14UnsupportedProposalIsLimitation(t *testing.T) {
	r := c14Report(t, func(r *FalsifierReport) {
		r.Proofs[0].Status = FalsifierUnknown
		r.Proofs[0].Basis = BasisUnsupported
		r.Proofs[0].Coverage = FalsifierCoverage{}
		r.Proofs[0].History = []FalsifierTransition{{From: FalsifierUnknown, To: FalsifierUnknown, Reason: "mandatory condition source unsupported"}}
	})
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckUnverified {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14ProofHashMismatchIsTechnical: a tampered report is never absorbed.
func TestC14ProofHashMismatchIsTechnical(t *testing.T) {
	r := c14Report(t, nil)
	r.Proofs[0].Mandatory = false
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckInvalid {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
	if !strings.Contains(strings.Join(got.Reasons, "|"), "hash does not match") {
		t.Fatalf("reasons=%v", got.Reasons)
	}
}

// TestC14ForeignSnapshotIsTechnical: proofs bound to another snapshot never
// pass the gate of this package.
func TestC14ForeignSnapshotIsTechnical(t *testing.T) {
	r := c14Report(t, func(r *FalsifierReport) { r.Proofs[0].Coverage.SnapshotHash = "other-snapshot" })
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status != CheckInvalid {
		t.Fatalf("status=%s reasons=%v", got.Status, got.Reasons)
	}
}

// TestC14ForeignKeyStability: C14 keys and order are part of the check set.
func TestC14DefaultChecksIncludeFalsifierProof(t *testing.T) {
	last := ""
	for _, c := range DefaultChecks() {
		last = c.ID()
	}
	if last != CheckIDFalsifierProof {
		t.Fatalf("last check = %s, want %s", last, CheckIDFalsifierProof)
	}
	// C14 needs the composed package and the admitted facts, so it must not
	// run in the pre-package set.
	for _, c := range PrePackageChecks() {
		if c.ID() == CheckIDFalsifierProof {
			t.Fatal("C14 must run at the final gate only")
		}
	}
}

// TestC14VerifiedCodeAbsentNeedsClosure: a VERIFIED code_absent proof
// that omits the import-closure record is forged — every other field can
// be complete and the gate still refuses.
func TestC14VerifiedCodeAbsentNeedsClosure(t *testing.T) {
	for name, strip := range map[string]func(c *FalsifierCoverage){
		"missing closure hash":   func(c *FalsifierCoverage) { c.ClosureHash = "" },
		"incomplete closure":     func(c *FalsifierCoverage) { c.ClosureComplete = false },
		"missing absent set":     func(c *FalsifierCoverage) { c.AbsentSubjects = nil },
		"open exceptions":        func(c *FalsifierCoverage) { c.OpenExceptions = []string{"plugin at depa imports plugin"} },
		"stale rule version":     func(c *FalsifierCoverage) { c.CoverageRuleVersion = "2" },
		"missing rule version":   func(c *FalsifierCoverage) { c.CoverageRuleVersion = "" },
		"present subject listed": func(c *FalsifierCoverage) { c.PresentSubjects = c.AbsentSubjects },
	} {
		r := c14Report(t, func(r *FalsifierReport) { strip(&r.Proofs[0].Coverage) })
		got := c14Run(t, c14Input(t, r, nil))
		if got.Status != CheckInvalid {
			t.Fatalf("%s: status=%s reasons=%v", name, got.Status, got.Reasons)
		}
	}
}

// TestC14MixedSubjectsPresentNeverVerified: a group containing one present
// subject is a contradiction even when another subject is absent and the
// closure itself is complete.
func TestC14MixedSubjectsPresentNeverVerified(t *testing.T) {
	r := c14Report(t, func(r *FalsifierReport) {
		c := &r.Proofs[0].Coverage
		present := FalsifierSubject{Package: "example.org/p", Symbol: "Wrapper"}
		c.ExpectedSubjects = append(c.ExpectedSubjects, present)
		c.CheckedSubjects = append(c.CheckedSubjects, present)
		c.PresentSubjects = []FalsifierSubject{present}
	})
	got := c14Run(t, c14Input(t, r, nil))
	if got.Status == CheckPass {
		t.Fatalf("mixed present/absent subjects admitted: %+v", got)
	}
}

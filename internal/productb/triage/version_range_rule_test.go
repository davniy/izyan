package triage

import (
	"context"
	"strings"
	"testing"
)

// TestComposerVersionOutsideRangeDismissed pins the deterministic dismissal:
// a confirmed resolved version outside every affected range removes the
// finding without any agent proof, and the package names the rule.
func TestComposerVersionOutsideRangeDismissed(t *testing.T) {
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(),
		versionRangeStage0(CheckVersionConfirmed), goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("recommendation = %s (demotions=%v)", pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Demotions)
	}
	if !strings.Contains(strings.Join(pkg.MachineDisposition.Rationale.Basis, "|"), "rule version-outside-affected-range satisfied") {
		t.Fatalf("rule basis = %v", pkg.MachineDisposition.Rationale.Basis)
	}

	// The dismissal projects to VEX as vulnerable_code_not_present, grounded
	// on the affected fact — an unvalidated proposal is never involved.
	proj, err := ProjectVEX(pkg)
	if err != nil {
		t.Fatalf("VEX projection: %v", err)
	}
	if proj.Justification != vexJustificationCodeNotPresent {
		t.Fatalf("justification = %q", proj.Justification)
	}
}

// TestComposerVersionOutsideRangeRequiresConfirmedChain pins the boundary:
// the rule never fires without a confirmed comparison — a version mismatch,
// an affected version or an advisory without ranges all stay UNCHANGED.
func TestComposerVersionOutsideRangeRequiresConfirmedChain(t *testing.T) {
	for name, s0 := range map[string]Stage0Result{
		"version mismatch":          versionRangeStage0(CheckVersionMismatch),
		"version in affected range": versionRangeStage0(CheckAffectedRange),
		"module absent":             versionRangeStage0(CheckModuleAbsent),
	} {
		pkg, err := Composer{}.ComposeWithEvidence(context.Background(), s0, goodAssessment(), completeValidation(), EvidenceInput{})
		if err != nil {
			t.Fatalf("%s: compose: %v", name, err)
		}
		if name == "module absent" {
			// Absence keeps its own, stronger falsifier rule.
			if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
				t.Fatalf("module absent = %s", pkg.MachineDisposition.Recommendation)
			}
			if !strings.Contains(strings.Join(pkg.MachineDisposition.Rationale.Basis, "|"), "rule module-absent-falsifier satisfied") {
				t.Fatalf("module absent rule = %v", pkg.MachineDisposition.Rationale.Basis)
			}
			continue
		}
		if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
			t.Fatalf("%s dismissed (basis=%v)", name, pkg.MachineDisposition.Rationale.Basis)
		}
	}

	// Advisory without affected ranges: VERSION_CONFIRMED still yields an
	// undecidable affected fact, never a dismissal.
	bare := versionRangeStage0(CheckVersionConfirmed)
	bare.Resolution.Projection.AffectedVersions = nil
	bare.Resolution.Projection.FixedVersions = nil
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), bare, goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("bare compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatalf("range-less advisory dismissed (basis=%v)", pkg.MachineDisposition.Rationale.Basis)
	}
}

// TestComposerVersionOutsideRangeRequiresFullAdvisory pins the false-safe
// boundary of the rule: a partial (ticket-projected) advisory cannot ground
// an applicability claim, so the same facts stay UNCHANGED.
func TestComposerVersionOutsideRangeRequiresFullAdvisory(t *testing.T) {
	s0 := versionRangeStage0(CheckVersionConfirmed)
	s0.Resolution.Partial = true
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), s0, goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatalf("partial advisory dismissed (basis=%v)", pkg.MachineDisposition.Rationale.Basis)
	}
}

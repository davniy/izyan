package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/evidencetools"
)

// humanOnlyAssessment is the fixture the human-result tests compose: the
// model judgment is an explicit interpretation, the proposed action is a
// concrete CLOSE, and the decisive premise is an interpretation grounded in
// a verified quotation — no admitted proof, no measured fact.
func humanOnlyAssessment() Assessment {
	a := goodAssessment()
	a.Verdict = VerdictNotExploitable
	a.Summary = "the vulnerable parser is never invoked by the captured entry points"
	a.Mechanism = "the only parser references sit behind a build tag the release binary does not set"
	a.Claims = []Claim{{
		ID:               "c1",
		Statement:        "the captured build contains no call into the vulnerable parser",
		Basis:            PremiseInterpreted,
		Subject:          "call-path reachability",
		Scope:            "captured snapshot",
		DecisionRelevant: true,
		EvidenceRefs:     []string{"ev-1"},
		Binding:          &PremiseBinding{Kind: BindingQuotedText, ReferenceID: "ev-1"},
	}}
	a.Evidence = []EvidenceRef{{
		ID: "ev-1", Kind: "file", Locator: "internal/parser/parser.go",
		Quote: "func parse(", SHA256: strings.Repeat("cd", 32),
	}}
	a.ProposedAction = closeAction("c1")
	return a
}

// undecidedStage0 is the Stage 0 fixture in which no admitted rule can fire:
// presence is undecidable, the module graph is partial and the deployment
// perimeter is unknown. The machine disposition therefore stays UNCHANGED.
func undecidedStage0() Stage0Result {
	s0 := goodStage0()
	s0.Materials.ModuleGraph.Complete = false
	s0.Materials.Deploy = nil
	s0.PackageCheck = PackageCheckResult{
		Class:       CheckUnresolved,
		ClaimedPath: "example.org/library",
		Reason:      "module presence is undecidable over the captured graph",
		Limitations: []string{"module graph is partial"},
	}
	return s0
}

// observedStage0 is the fixture in which the module-absence rule fires: the
// machine layer, not the model, owns the dismissal.
func observedStage0() Stage0Result {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{
		Class:          CheckModuleAbsent,
		ClaimedPath:    "example.org/library",
		EvidenceSource: "module_graph",
		Reason:         "module example.org/library absent from the complete module graph",
		Provenance:     []string{"go list -m all"},
	}
	return s0
}

// measuredObservation is a recorded, digest-verified observation of attempt
// 1 bound to the fixture snapshot; its narrow fact is the claim statement the
// measured fixture asserts.
func measuredObservation(t *testing.T) RecordedObservation {
	t.Helper()
	payload := json.RawMessage(`{"fact":"module example.org/library is not in the build graph"}`)
	sum := sha256.Sum256(payload)
	return RecordedObservation{
		ID:           "obs-1",
		Tool:         "get_dependency_graph",
		Status:       string(ToolStatusOK),
		Completeness: evidencetools.CompletenessComplete,
		Scope:        "build-graph",
		Payload:      payload,
		DataSHA256:   hex.EncodeToString(sum[:]),
		SnapshotHash: strings.Repeat("cd", 32),
		RunID:        "run-1",
		Attempt:      1,
	}
}

// measuredAssessment grounds its decisive premise in a recorded observation.
func measuredAssessment() Assessment {
	a := goodAssessment()
	a.Claims[0].Statement = "module example.org/library is not in the build graph"
	a.Claims[0].Scope = "build-graph"
	return a
}

// TestComposerSeparatesJudgmentActionAndMachineDisposition pins the core v3
// contract: an interpreted negative judgment and a CLOSE proposal coexist
// with LIMITED support and a machine disposition that establishes nothing.
// The four axes are read from their own fields and never from each other.
func TestComposerSeparatesJudgmentActionAndMachineDisposition(t *testing.T) {
	pkg := composeOrFail(t, undecidedStage0(), humanOnlyAssessment(), completeValidation())

	if pkg.Judgment.Verdict != VerdictNotExploitable ||
		pkg.Judgment.Summary != "the vulnerable parser is never invoked by the captured entry points" ||
		pkg.Judgment.Mechanism == "" {
		t.Fatalf("judgment not preserved verbatim: %+v", pkg.Judgment)
	}
	if pkg.ProposedAction.Kind != HumanActionClose ||
		pkg.ProposedAction.Instruction != "close the ticket as not exploitable" ||
		len(pkg.ProposedAction.ReconsiderWhen) == 0 {
		t.Fatalf("proposed action not preserved verbatim: %+v", pkg.ProposedAction)
	}
	if pkg.Support.Level != SupportLevelLimited {
		t.Fatalf("support = %s, want LIMITED for an interpretation-only premise graph (reasons=%v)",
			pkg.Support.Level, pkg.Support.Reasons)
	}
	if got := pkg.MachineDisposition.Recommendation; got != RecommendationUnchanged {
		t.Fatalf("machine recommendation = %s, want UNCHANGED", got)
	}
	if pkg.MachineDisposition.Automation != AutomationWarn {
		t.Fatalf("automation = %s, want WARN without a machine reduction", pkg.MachineDisposition.Automation)
	}
	if len(pkg.Premises) != 1 || pkg.Premises[0].ClaimID != "c1" || pkg.Premises[0].Basis != PremiseInterpreted {
		t.Fatalf("derived premises wrong: %+v", pkg.Premises)
	}
	// Structural separation: the machine rationale is deterministic prose and
	// never a copy of the model's judgment or action prose.
	if pkg.MachineDisposition.Rationale.Summary == pkg.Judgment.Summary ||
		strings.Contains(pkg.MachineDisposition.Rationale.Summary, pkg.ProposedAction.Instruction) {
		t.Fatalf("machine rationale copied human prose: %+v", pkg.MachineDisposition.Rationale)
	}
	if err := pkg.Validate(); err != nil {
		t.Fatalf("separated package violates the contract: %v", err)
	}
}

// TestComposerWithoutSeverityReturnsHumanPackage pins the optional-baseline
// contract: a finding with no severity anywhere still yields the complete
// human package. The machine disposition records the withheld reduction, no
// severity/priority is synthesized, and support is unaffected.
func TestComposerWithoutSeverityReturnsHumanPackage(t *testing.T) {
	withoutSeverity := composeOrFail(t, noSeverityStage0(), humanOnlyAssessment(), completeValidation())

	if withoutSeverity.MachineDisposition.Baseline != nil {
		t.Fatalf("absent severity must leave the baseline absent: %+v", withoutSeverity.MachineDisposition.Baseline)
	}
	if got := withoutSeverity.MachineDisposition.Recommendation; got != RecommendationUnchanged {
		t.Fatalf("machine recommendation = %s, want UNCHANGED without a baseline", got)
	}
	// The reason is recorded inside the machine disposition, not as a human
	// action and not as a severity invention.
	if !hasLimitationContaining(withoutSeverity.TechnicalAssessment.Limitations, "no authoritative severity baseline") {
		t.Fatalf("the absent baseline is not recorded: %v", withoutSeverity.TechnicalAssessment.Limitations)
	}
	demoted := false
	for _, d := range withoutSeverity.MachineDisposition.Demotions {
		if strings.Contains(d, "severity baseline") {
			demoted = true
		}
	}
	if !demoted {
		t.Fatalf("the withheld reduction is not recorded: %v", withoutSeverity.MachineDisposition.Demotions)
	}
	if withoutSeverity.MachineDisposition.Automation != AutomationWarn {
		t.Fatalf("automation = %s, want WARN", withoutSeverity.MachineDisposition.Automation)
	}
	// The human result is intact and identical to the case with severity.
	wantJudgment := LLMJudgment{
		Verdict:   VerdictNotExploitable,
		Summary:   "the vulnerable parser is never invoked by the captured entry points",
		Mechanism: "the only parser references sit behind a build tag the release binary does not set",
	}
	if withoutSeverity.Judgment != wantJudgment {
		t.Fatalf("judgment damaged by the missing baseline: %+v", withoutSeverity.Judgment)
	}
	if !reflect.DeepEqual(withoutSeverity.ProposedAction, humanOnlyAssessment().ProposedAction) {
		t.Fatalf("proposed action damaged by the missing baseline: %+v", withoutSeverity.ProposedAction)
	}
	withSeverity := composeOrFail(t, goodStage0(), humanOnlyAssessment(), completeValidation())
	if withSeverity.MachineDisposition.Baseline == nil {
		t.Fatal("fixture lost its advisory severity")
	}
	if withoutSeverity.Support.Level != withSeverity.Support.Level {
		t.Fatalf("missing severity changed the derived support: %s != %s",
			withoutSeverity.Support.Level, withSeverity.Support.Level)
	}
	// The wire form carries no synthesized severity/priority block.
	data, err := json.Marshal(withoutSeverity)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		MachineDisposition map[string]any `json:"machine_disposition"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire.MachineDisposition["baseline"]; ok {
		t.Fatalf("machine_disposition invented a baseline: %v", wire.MachineDisposition)
	}
}

// TestHumanProposalCannotAuthorizeMachineReduction pins false-safe = 0 at the
// package level: CLOSE and LOWER_PRIORITY proposals are actions for a person.
// They never produce a machine reduction, never satisfy a VEX prerequisite
// and never authorize an automatic action.
func TestHumanProposalCannotAuthorizeMachineReduction(t *testing.T) {
	for _, kind := range []HumanActionKind{HumanActionClose, HumanActionLowerPriority} {
		t.Run(string(kind), func(t *testing.T) {
			a := humanOnlyAssessment()
			a.ProposedAction.Kind = kind
			pkg := composeOrFail(t, undecidedStage0(), a, completeValidation())

			if pkg.ProposedAction.Kind != kind {
				t.Fatalf("the proposal was rewritten: %+v", pkg.ProposedAction)
			}
			if got := pkg.MachineDisposition.Recommendation; got != RecommendationUnchanged {
				t.Fatalf("a human %s proposal produced machine %s", kind, got)
			}
			if pkg.MachineDisposition.Automation != AutomationWarn {
				t.Fatalf("automation = %s, want WARN", pkg.MachineDisposition.Automation)
			}
			// A policy hit here is a delivery signal, never a safety claim.
			if !PackagePolicyHit(pkg, FailOnUnchanged) {
				t.Fatal("an unchanged machine disposition must trip the unchanged threshold")
			}
			// Neither the proposal nor the support can satisfy a VEX
			// prerequisite: the projection reads the machine disposition only.
			if _, err := ProjectVEX(pkg); err == nil {
				t.Fatal("a human proposal authorized a VEX projection")
			}
			for _, line := range append(append([]string{}, pkg.MachineDisposition.Demotions...), pkg.TechnicalAssessment.Limitations...) {
				if strings.Contains(strings.ToLower(line), string(kind)) {
					t.Fatalf("the machine record treats the human proposal as a premise: %q", line)
				}
			}
		})
	}
}

// TestSupportDoesNotChangeMachineDisposition pins the axis independence: the
// same machine inputs with a measured, grounded premise (SUBSTANTIATED) and
// with an attempt-mismatched premise (LIMITED) produce byte-identical machine
// dispositions. Support is a property of the human action's grounds, never an
// admission signal.
func TestSupportDoesNotChangeMachineDisposition(t *testing.T) {
	obs := measuredObservation(t)
	a := measuredAssessment()
	s0 := observedStage0()

	grounded, err := (Composer{}).ComposeWithEvidence(context.Background(), s0, a, completeValidation(), EvidenceInput{
		Observations:    []RecordedObservation{obs},
		SelectedAttempt: 1,
	})
	if err != nil {
		t.Fatalf("compose grounded: %v", err)
	}
	ungrounded, err := (Composer{}).ComposeWithEvidence(context.Background(), s0, a, completeValidation(), EvidenceInput{
		Observations:    []RecordedObservation{obs},
		SelectedAttempt: 2,
	})
	if err != nil {
		t.Fatalf("compose ungrounded: %v", err)
	}

	if grounded.Support.Level != SupportLevelSubstantiated {
		t.Fatalf("grounded support = %s, want SUBSTANTIATED (reasons=%v)",
			grounded.Support.Level, grounded.Support.Reasons)
	}
	if ungrounded.Support.Level != SupportLevelLimited {
		t.Fatalf("ungrounded support = %s, want LIMITED (reasons=%v)",
			ungrounded.Support.Level, ungrounded.Support.Reasons)
	}
	if !reflect.DeepEqual(grounded.MachineDisposition, ungrounded.MachineDisposition) {
		t.Fatalf("support changed the machine disposition:\n grounded: %+v\nungrounded: %+v",
			grounded.MachineDisposition, ungrounded.MachineDisposition)
	}
	if grounded.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("machine recommendation = %s, want the admitted DISMISSED", grounded.MachineDisposition.Recommendation)
	}
	if grounded.MachineDisposition.Automation != AutomationAllow {
		t.Fatalf("automation = %s, want ALLOW for the admitted reduction", grounded.MachineDisposition.Automation)
	}
}

// TestMachineAutomationRequiresAdmittedReduction pins the end-to-end policy
// outcome: ALLOW requires a reduction the machine path actually admitted on a
// complete basis; a valid package without one WARNs; and a package whose
// machine prerequisites are invalid or failed BLOCKs.
func TestMachineAutomationRequiresAdmittedReduction(t *testing.T) {
	admitted := composeOrFail(t, observedStage0(), goodAssessment(), completeValidation())
	if admitted.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("admitted fixture = %s", admitted.MachineDisposition.Recommendation)
	}
	if admitted.MachineDisposition.Automation != AutomationAllow {
		t.Fatalf("admitted reduction automation = %s, want ALLOW", admitted.MachineDisposition.Automation)
	}

	unchanged := composeOrFail(t, undecidedStage0(), humanOnlyAssessment(), completeValidation())
	if unchanged.MachineDisposition.Automation != AutomationWarn {
		t.Fatalf("unchanged automation = %s, want WARN", unchanged.MachineDisposition.Automation)
	}

	partial := completeValidation()
	partial.Status = ValidationPartial
	withheld := composeOrFail(t, observedStage0(), goodAssessment(), partial)
	if withheld.MachineDisposition.Automation != AutomationWarn {
		t.Fatalf("partial-basis automation = %s, want WARN", withheld.MachineDisposition.Automation)
	}
	if withheld.MachineDisposition.Recommendation == RecommendationDismissed &&
		len(withheld.MachineDisposition.Demotions) > 0 {
		t.Fatalf("a demoted package must not be reported as an admitted reduction")
	}

	failed := completeValidation()
	failed.Status = ValidationFailed
	blocked := composeOrFail(t, observedStage0(), goodAssessment(), failed)
	if blocked.MachineDisposition.Automation != AutomationBlock {
		t.Fatalf("failed-basis automation = %s, want BLOCK", blocked.MachineDisposition.Automation)
	}

	// A package that records a demotion next to a reduction can never ALLOW:
	// the reduction was withdrawn, whatever the field says.
	forged := admitted
	forged.MachineDisposition.Demotions = []string{"rule x permitted DISMISSED; demoted to UNCHANGED: check C03 is UNAVAILABLE"}
	if got := EvaluateMachineAutomation(forged.MachineDisposition, ValidationComplete); got != AutomationBlock {
		t.Fatalf("forged reduction automation = %s, want BLOCK", got)
	}
}

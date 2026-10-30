package triage

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyFalseSafe preserves the hard machine-safety assertion: only the
// machine disposition is compared, a reduction beyond the authoritative
// control is ErrFalseSafe, and a missing control disposition cannot permit
// a reduction. A human proposal is never an input.
func TestVerifyFalseSafe(t *testing.T) {
	dismissed := metricsDecision(RecommendationDismissed, SupportLevelProvedWithinScope, AutomationAllow, 0, 0, false)
	unchanged := metricsDecision(RecommendationUnchanged, SupportLevelSubstantiated, AutomationWarn, 0, 0, false)
	lowered := metricsDecision(RecommendationLowered, SupportLevelSubstantiated, AutomationAllow, 0, 0, false)

	if err := VerifyFalseSafe(*unchanged, AuthoritativeBaseline{Disposition: RecommendationUnchanged}); err != nil {
		t.Fatalf("UNCHANGED flagged false-safe: %v", err)
	}
	if err := VerifyFalseSafe(*lowered, AuthoritativeBaseline{Disposition: RecommendationDismissed}); err != nil {
		t.Fatalf("LOWERED inside a DISMISSED-allowing baseline flagged: %v", err)
	}
	if err := VerifyFalseSafe(*dismissed, AuthoritativeBaseline{Disposition: RecommendationUnchanged}); !errors.Is(err, ErrFalseSafe) {
		t.Fatalf("DISMISSED over UNCHANGED baseline = %v, want ErrFalseSafe", err)
	}
	if err := VerifyFalseSafe(*lowered, AuthoritativeBaseline{Disposition: RecommendationUnchanged}); !errors.Is(err, ErrFalseSafe) {
		t.Fatalf("LOWERED over UNCHANGED baseline = %v, want ErrFalseSafe", err)
	}
	// An absent authoritative control disposition cannot permit a
	// reduction: baseline without a valid disposition + reduction is a
	// fail-closed error, UNCHANGED stays legal.
	if err := VerifyFalseSafe(*unchanged, AuthoritativeBaseline{}); err != nil {
		t.Fatalf("UNCHANGED without baseline flagged: %v", err)
	}
	if err := VerifyFalseSafe(*lowered, AuthoritativeBaseline{}); err == nil {
		t.Fatal("LOWERED without an authoritative baseline passed")
	}
	if err := VerifyFalseSafe(*metricsDecision("GARBAGE", SupportLevelSubstantiated, AutomationWarn, 0, 0, false), AuthoritativeBaseline{Disposition: RecommendationUnchanged}); err == nil {
		t.Fatal("invalid recommendation passed")
	}
	// The human proposal is not part of machine safety: a CLOSE proposal
	// over an UNCHANGED machine disposition is not a false-safe.
	humanClose := *unchanged
	humanClose.ProposedAction = HumanAction{Kind: HumanActionClose}
	if err := VerifyFalseSafe(humanClose, AuthoritativeBaseline{Disposition: RecommendationUnchanged}); err != nil {
		t.Fatalf("human CLOSE affected machine safety: %v", err)
	}
}

// TestVerifyFalseSafeRemainsHard migrates the production metrics hard gate
// to the offline evaluator: a DISMISSED machine recommendation against an
// UNCHANGED control is one machine false-safe with a measured violation.
func TestVerifyFalseSafeRemainsHard(t *testing.T) {
	p := metricsDecision(RecommendationDismissed, SupportLevelProvedWithinScope, AutomationAllow, 0, 0, false)
	p.RunID, p.FindingID = "run-hard", "finding-hard"
	b := AuthoritativeBaseline{Disposition: RecommendationUnchanged, Source: "authoritative"}
	if err := VerifyFalseSafe(*p, b); !errors.Is(err, ErrFalseSafe) {
		t.Fatalf("VerifyFalseSafe = %v, want ErrFalseSafe", err)
	}
	eval := EvaluateDecisionPackage(*p, &b)
	if eval.Machine.Reductions != 1 || eval.Machine.FalseSafe != 1 || eval.Machine.UnverifiedReductions != 0 {
		t.Fatalf("machine counters = %+v", eval.Machine)
	}
	if len(eval.Violations) != 1 || !strings.Contains(eval.Violations[0], "machine false-safe") {
		t.Fatalf("violations = %v", eval.Violations)
	}
}

// TestLoadBaselines exercises the offline triage-baselines.v1 document:
// entries keyed by finding_id, the optional expected_judgment and every
// malformed shape rejected.
func TestLoadBaselines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baselines.json")
	writeFile(t, path, `{"schema_version":"triage-baselines.v1","baselines":[
		{"finding_id":"f-a","disposition":"DISMISSED","expected_judgment":"EXPLOITABLE","severity":"medium","priority":"P3","source":"sec-team"},
		{"finding_id":"f-b","disposition":"UNCHANGED","source":"sec-team"}]}`)
	got, err := LoadBaselines(path)
	if err != nil {
		t.Fatalf("LoadBaselines: %v", err)
	}
	if len(got) != 2 || got["f-a"].Disposition != RecommendationDismissed || got["f-b"].Severity != "" {
		t.Fatalf("baselines = %+v", got)
	}
	if got["f-a"].ExpectedJudgment == nil || *got["f-a"].ExpectedJudgment != VerdictExploitable {
		t.Fatalf("expected_judgment = %+v", got["f-a"].ExpectedJudgment)
	}
	if got["f-b"].ExpectedJudgment != nil {
		t.Fatalf("absent expected_judgment = %+v, want nil", got["f-b"].ExpectedJudgment)
	}

	writeFile(t, path, `{"baselines":[{"finding_id":"f-x","disposition":"MAYBE"}]}`)
	if _, err := LoadBaselines(path); err == nil {
		t.Fatal("invalid disposition accepted")
	}
	writeFile(t, path, `{"baselines":[{"finding_id":"f-x","disposition":"UNCHANGED","expected_judgment":"NOT_AFFECTED"}]}`)
	if _, err := LoadBaselines(path); err == nil {
		t.Fatal("invalid expected_judgment accepted")
	}
	writeFile(t, path, `{"baselines":[{"disposition":"UNCHANGED"}]}`)
	if _, err := LoadBaselines(path); err == nil {
		t.Fatal("missing finding_id accepted")
	}
	writeFile(t, path, `{"schema_version":"triage-baselines.v2","baselines":[]}`)
	if _, err := LoadBaselines(path); err == nil {
		t.Fatal("unknown schema version accepted")
	}
	writeFile(t, path, `{`)
	if _, err := LoadBaselines(path); err == nil {
		t.Fatal("broken JSON accepted")
	}
	if _, err := LoadBaselines(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("missing file accepted")
	}
}

// TestDecisionEvaluationSeparatesHumanAndMachineErrors pins the offline
// comparison contract: human recommendation mistakes are not machine
// false-safes, external judgment labels are a separate comparison, absent
// controls are unassessed coverage, and evaluation never mutates the
// package or its rendered action.
func TestDecisionEvaluationSeparatesHumanAndMachineErrors(t *testing.T) {
	humanClose := metricsDecision(RecommendationUnchanged, SupportLevelSubstantiated, AutomationWarn, 0, 0, false)
	humanClose.RunID, humanClose.FindingID = "run-eval", "finding-eval"
	humanClose.Judgment = LLMJudgment{Verdict: VerdictNotExploitable}
	humanClose.ProposedAction = HumanAction{Kind: HumanActionClose}
	packageHash := canonicalDecisionHash(*humanClose)
	renderedAction := string(RenderDecisionMarkdown(*humanClose))

	// 1. An incorrect CLOSE proposal with machine UNCHANGED against an
	// UNCHANGED control is a human recommendation error, not a machine
	// false-safe.
	baseline := &AuthoritativeBaseline{Disposition: RecommendationUnchanged, Source: "control"}
	eval := EvaluateDecisionPackage(*humanClose, baseline)
	if eval.Coverage.ControlDisposition != ComparisonAssessed {
		t.Fatalf("control coverage = %q", eval.Coverage.ControlDisposition)
	}
	if eval.Coverage.ExpectedJudgment != ComparisonUnassessed {
		t.Fatalf("absent expected_judgment coverage = %q, want %q", eval.Coverage.ExpectedJudgment, ComparisonUnassessed)
	}
	if eval.Human.ReductionProposals != 1 || eval.Human.ReductionControlMismatches != 1 {
		t.Fatalf("human counters = %+v", eval.Human)
	}
	if eval.Machine.Reductions != 0 || eval.Machine.FalseSafe != 0 {
		t.Fatalf("machine counters = %+v, want no machine reduction", eval.Machine)
	}
	if len(eval.Violations) != 1 || !strings.Contains(eval.Violations[0], "human reduction control mismatch") {
		t.Fatalf("violations = %v", eval.Violations)
	}

	// 2. A negative judgment against an external EXPLOITABLE label is a
	// separate human error; CLOSE on the same case is counted separately
	// again.
	expected := VerdictExploitable
	labelled := *baseline
	labelled.ExpectedJudgment = &expected
	eval = EvaluateDecisionPackage(*humanClose, &labelled)
	if eval.Coverage.ExpectedJudgment != ComparisonAssessed {
		t.Fatalf("expected_judgment coverage = %q", eval.Coverage.ExpectedJudgment)
	}
	if eval.Human.NegativeJudgments != 1 || eval.Human.IncorrectNegativeJudgments != 1 || eval.Human.CloseOnExploitable != 1 {
		t.Fatalf("human counters = %+v", eval.Human)
	}
	if eval.Human.ReductionControlMismatches != 1 || eval.Machine.FalseSafe != 0 {
		t.Fatalf("axes mixed: %+v / %+v", eval.Human, eval.Machine)
	}

	// 3. A machine reduction beyond the supplied control remains the hard
	// ErrFalseSafe and is counted on the machine axis only.
	unsafe := metricsDecision(RecommendationDismissed, SupportLevelProvedWithinScope, AutomationAllow, 0, 0, false)
	unsafe.RunID, unsafe.FindingID = "run-unsafe", "finding-unsafe"
	if err := VerifyFalseSafe(*unsafe, *baseline); !errors.Is(err, ErrFalseSafe) {
		t.Fatalf("VerifyFalseSafe = %v, want ErrFalseSafe", err)
	}
	eval = EvaluateDecisionPackage(*unsafe, baseline)
	if eval.Machine.Reductions != 1 || eval.Machine.FalseSafe != 1 || eval.Machine.UnverifiedReductions != 0 {
		t.Fatalf("machine counters = %+v", eval.Machine)
	}
	if eval.Human.ReductionControlMismatches != 0 {
		t.Fatalf("machine false-safe leaked into human counters: %+v", eval.Human)
	}

	// 4. Missing control and GT are unassessed coverage, never fabricated
	// correct results: the reduction is unverified, not a violation.
	eval = EvaluateDecisionPackage(*unsafe, nil)
	if eval.Coverage.ControlDisposition != ComparisonUnassessed || eval.Coverage.ExpectedJudgment != ComparisonUnassessed {
		t.Fatalf("missing coverage = %+v", eval.Coverage)
	}
	if eval.Machine.Reductions != 1 || eval.Machine.UnverifiedReductions != 1 || eval.Machine.FalseSafe != 0 {
		t.Fatalf("unassessed machine counters = %+v", eval.Machine)
	}
	if len(eval.Violations) != 0 {
		t.Fatalf("missing control fabricated violations: %v", eval.Violations)
	}

	// 5. Changing the external baseline cannot change the package hash or
	// its rendered action.
	other := *baseline
	other.Disposition = RecommendationDismissed
	other.Source = "other-control"
	other.ExpectedJudgment = &expected
	_ = EvaluateDecisionPackage(*humanClose, &other)
	if got := canonicalDecisionHash(*humanClose); got != packageHash {
		t.Fatalf("package hash changed by evaluation: %s -> %s", packageHash, got)
	}
	if got := string(RenderDecisionMarkdown(*humanClose)); got != renderedAction {
		t.Fatal("rendered action changed by evaluation")
	}
	if humanClose.ProposedAction.Kind != HumanActionClose || humanClose.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("package mutated: %+v", humanClose)
	}
}

// TestDecisionEvaluationWrittenArtifact pins the persisted report identity
// and the separate counters; the package files themselves are untouched.
func TestDecisionEvaluationWrittenArtifact(t *testing.T) {
	pkg := metricsDecision(RecommendationUnchanged, SupportLevelSubstantiated, AutomationWarn, 0, 0, false)
	pkg.RunID, pkg.FindingID = "run-write", "finding-write"
	pkg.Judgment = LLMJudgment{Verdict: VerdictNotExploitable}
	pkg.ProposedAction = HumanAction{Kind: HumanActionClose}
	expected := VerdictExploitable
	baseline := &AuthoritativeBaseline{
		Disposition:      RecommendationUnchanged,
		ExpectedJudgment: &expected,
		Source:           "external-control",
	}
	eval := EvaluateDecisionPackage(*pkg, baseline)
	dir := t.TempDir()
	path, err := WriteDecisionEvaluation(context.Background(), dir, eval)
	if err != nil {
		t.Fatalf("WriteDecisionEvaluation: %v", err)
	}
	if filepath.Base(path) != "evaluation.json" || filepath.Dir(path) != dir {
		t.Fatalf("evaluation path = %s", path)
	}
	var doc DecisionEvaluation
	if err := json.Unmarshal(mustRead(t, path), &doc); err != nil {
		t.Fatalf("evaluation.json does not parse: %v", err)
	}
	if doc.SchemaVersion != EvaluationSchemaVersion || doc.EvaluatedAt == "" {
		t.Fatalf("evaluation identity = %q / %q", doc.SchemaVersion, doc.EvaluatedAt)
	}
	if doc.RunID != pkg.RunID || doc.FindingID != pkg.FindingID || doc.DecisionPackageHash != canonicalDecisionHash(*pkg) {
		t.Fatalf("evaluation package identity = %+v", doc)
	}
	if doc.Coverage.ControlDisposition != ComparisonAssessed || doc.Coverage.ExpectedJudgment != ComparisonAssessed {
		t.Fatalf("evaluation coverage = %+v", doc.Coverage)
	}
	if doc.Human.ReductionControlMismatches != 1 || doc.Human.IncorrectNegativeJudgments != 1 ||
		doc.Human.CloseOnExploitable != 1 || doc.Machine.FalseSafe != 0 {
		t.Fatalf("evaluation counters = human:%+v machine:%+v", doc.Human, doc.Machine)
	}
}

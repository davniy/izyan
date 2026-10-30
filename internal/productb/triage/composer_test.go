package triage

import (
	"context"
	"strings"
	"testing"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// composeOrFail composes with the default providers and auto-run checks.
func composeOrFail(t *testing.T, s0 Stage0Result, a Assessment, fv FactValidation) DecisionPackage {
	t.Helper()
	pkg, err := ComposeDecision(context.Background(), s0, a, fv, nil, nil)
	if err != nil {
		t.Fatalf("ComposeDecision: %v", err)
	}
	if err := pkg.Validate(); err != nil {
		t.Fatalf("composed package failed validation: %v", err)
	}
	return pkg
}

// TestComposerMatrix runs the spec §6.5 recommendation matrix end to end:
// every row composes a real decision-package.v1 from a Stage 0 fixture —
// no fabricated recommendation is ever injected.
func TestComposerMatrix(t *testing.T) {
	t.Run("dismissed on proven module absence", func(t *testing.T) {
		s0 := goodStage0()
		s0.PackageCheck = PackageCheckResult{
			Class:          CheckModuleAbsent,
			ClaimedPath:    "example.org/library",
			EvidenceSource: "module_graph",
			Reason:         "module example.org/library absent from the complete module graph",
			Provenance:     []string{"go list -m all"},
		}
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
			t.Fatalf("recommendation = %s, want DISMISSED (demotions=%v)", pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Demotions)
		}
		if pkg.MachineDisposition.Baseline.Disposition != RecommendationUnchanged || pkg.MachineDisposition.Baseline.Severity != "HIGH" {
			t.Fatalf("baseline wrong: %+v", pkg.MachineDisposition.Baseline)
		}
		var presence *DecisionFact
		for i := range pkg.Facts {
			if pkg.Facts[i].Kind == FactPackagePresence {
				presence = &pkg.Facts[i]
			}
		}
		if presence == nil || presence.Status != ObsRefutes || presence.Scope != "build-graph" {
			t.Fatalf("package_presence fact missing or wrong: %+v", presence)
		}
		if pkg.MachineDisposition.RecommendedProfile.ID == "" {
			t.Fatal("recommended_profile must always be named")
		}
	})

	t.Run("lowered on proven cluster perimeter with affected version", func(t *testing.T) {
		pkg := composeOrFail(t, goodStage0(), goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationLowered {
			t.Fatalf("recommendation = %s, want LOWERED (demotions=%v)", pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Demotions)
		}
		if pkg.MachineDisposition.RecommendedProfile.ID != "internal-service" {
			t.Fatalf("profile = %q, want internal-service", pkg.MachineDisposition.RecommendedProfile.ID)
		}
	})

	t.Run("unchanged when the lowering premise stays unknown", func(t *testing.T) {
		s0 := goodStage0()
		s0.Materials.Deploy = &DeployFacts{Perimeter: domain.PerimeterUnknown}
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("recommendation = %s, want UNCHANGED", pkg.MachineDisposition.Recommendation)
		}
		if len(pkg.MachineDisposition.ConditionalProfiles) == 0 {
			t.Fatal("internal-service must surface as a conditional profile while exposure is UNKNOWN")
		}
		if pkg.MachineDisposition.ConditionalProfiles[0].Profile != "internal-service" ||
			pkg.MachineDisposition.ConditionalProfiles[0].Applicability.Status != ConditionUnknown {
			t.Fatalf("conditional profile wrong: %+v", pkg.MachineDisposition.ConditionalProfiles[0])
		}
	})

	t.Run("unchanged on a conflicting decision fact", func(t *testing.T) {
		s0 := goodStage0()
		s0.PackageCheck.Class = CheckVersionMismatch
		s0.PackageCheck.Reason = "claimed v1.9.9 conflicts with resolved v1.2.3"
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("recommendation = %s, want UNCHANGED on contradiction", pkg.MachineDisposition.Recommendation)
		}
		if len(pkg.TechnicalAssessment.Limitations) == 0 {
			t.Fatal("contradiction must be recorded as a limitation")
		}
	})

	t.Run("local empty search is never dismissal", func(t *testing.T) {
		s0 := goodStage0()
		s0.Materials.ModuleGraph.Complete = false
		s0.PackageCheck = PackageCheckResult{
			Class:       CheckUnresolved,
			ClaimedPath: "example.org/library",
			Reason:      "module graph incomplete; presence undecidable",
			Limitations: []string{"module graph is partial"},
		}
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("local empty search must not dismiss/lower, got %s", pkg.MachineDisposition.Recommendation)
		}
	})

	t.Run("malformed structured assessment is a technical error", func(t *testing.T) {
		a := goodAssessment()
		a.Verdict = "SOME_VERDICT"
		if _, err := ComposeDecision(context.Background(), goodStage0(), a, completeValidation(), nil, nil); err == nil {
			t.Fatal("invalid verdict must be a technical error, never a package")
		}
	})

	t.Run("missing baseline withholds the machine disposition", func(t *testing.T) {
		// The advisory and the pinned snapshot stay captured — only severity
		// metadata is absent. A fixture without advisory material would trip
		// the earlier missing-input rule (only OBTAIN_EVIDENCE is deliverable
		// then), which is not what this row proves.
		s0 := noSeverityStage0()
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Baseline != nil {
			t.Fatalf("absent severity must not mint a baseline: %+v", pkg.MachineDisposition.Baseline)
		}
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("machine recommendation = %s, want UNCHANGED without a baseline", pkg.MachineDisposition.Recommendation)
		}
	})

	t.Run("exploitable verdict contradicts a permitted reduction", func(t *testing.T) {
		s0 := goodStage0()
		s0.PackageCheck = PackageCheckResult{
			Class: CheckModuleAbsent, ClaimedPath: "example.org/library",
			EvidenceSource: "module_graph", Provenance: []string{"go list -m all"},
		}
		a := goodAssessment()
		a.Verdict = VerdictExploitable
		pkg := composeOrFail(t, s0, a, completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("agent contradiction must demote to UNCHANGED, got %s", pkg.MachineDisposition.Recommendation)
		}
	})
}

func TestPackageAbsent(t *testing.T) {
	t.Run("complete graph is a dismissal ground", func(t *testing.T) {
		s0 := goodStage0()
		s0.PackageCheck = PackageCheckResult{Class: CheckModuleAbsent, ClaimedPath: "example.org/library", EvidenceSource: "vendor/modules.txt", Provenance: []string{"vendor/modules.txt"}}
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
			t.Fatalf("complete absence = %s demotions=%v", pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Demotions)
		}
		if !pkg.Support.Level.Valid() {
			t.Fatalf("complete absence derived no support level: %+v", pkg.Support)
		}
		if !hasFact(pkg.Facts, FactComponentNotPresent, ObsSupports) {
			t.Fatalf("missing component_not_present SUPPORTS fact: %+v", pkg.Facts)
		}
	})
	t.Run("incomplete graph cannot establish absence", func(t *testing.T) {
		s0 := goodStage0()
		s0.Materials.ModuleGraph.Complete = false
		s0.PackageCheck = PackageCheckResult{Class: CheckModuleAbsent, ClaimedPath: "example.org/library", Reason: "absence from partial graph"}
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged || len(pkg.TechnicalAssessment.Limitations) == 0 {
			t.Fatalf("incomplete absence = %s limitations=%v", pkg.MachineDisposition.Recommendation, pkg.TechnicalAssessment.Limitations)
		}
	})

	t.Run("complete absence survives missing optional fields", func(t *testing.T) {
		s0 := goodStage0()
		s0.PackageCheck = PackageCheckResult{
			Class:          CheckModuleAbsent,
			ClaimedPath:    "example.org/library",
			EvidenceSource: "vendor/modules.txt",
			Provenance:     []string{"vendor/modules.txt"},
		}
		// Optional extraction lanes absent — they are not decision-relevant
		// and must not poison a proven falsifier (review fix).
		for _, f := range []string{"summary", "source_hints", "go_version", "release", "ref_hint", "aliases"} {
			s0.Validation.Fields = append(s0.Validation.Fields, FieldValidation{
				Field: f, Status: IntakeUnavailable,
			})
		}
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
			t.Fatalf("absent optional fields poisoned the falsifier: rec=%s demotions=%v limitations=%v",
				pkg.MachineDisposition.Recommendation,
				pkg.MachineDisposition.Demotions, pkg.TechnicalAssessment.Limitations)
		}
	})

	t.Run("unavailable decision-relevant field still demotes", func(t *testing.T) {
		s0 := goodStage0()
		s0.PackageCheck = PackageCheckResult{
			Class:          CheckModuleAbsent,
			ClaimedPath:    "example.org/library",
			EvidenceSource: "module_graph",
			Provenance:     []string{"go list -m all"},
		}
		for i := range s0.Validation.Fields {
			if s0.Validation.Fields[i].Field == "vulnerability_ids" {
				s0.Validation.Fields[i].Status = IntakeUnavailable
				s0.Validation.Fields[i].Provenance = nil
				s0.Validation.Fields[i].BlocksRiskReduction = true
			}
		}
		pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
		if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
			t.Fatalf("unavailable decision-relevant field must demote, got %s", pkg.MachineDisposition.Recommendation)
		}
		if len(pkg.MachineDisposition.Demotions) == 0 {
			t.Fatal("the demotion must be recorded")
		}
	})
}

func TestComposerBaselineDefault(t *testing.T) {
	t.Run("configured default produces a valid package", func(t *testing.T) {
		pkg, err := (Composer{DefaultBaselineSeverity: "medium"}).Compose(
			context.Background(), noSeverityStage0(), goodAssessment(), completeValidation(), nil)
		if err != nil {
			t.Fatalf("Compose with baseline.default_severity must succeed: %v", err)
		}
		b := *pkg.MachineDisposition.Baseline
		if b.Severity != "MEDIUM" || b.Source != "config:baseline.default_severity" || !b.Disposition.Valid() || b.Priority == "" {
			t.Fatalf("configured baseline wrong: %+v", b)
		}
		if !hasLimitationContaining(pkg.TechnicalAssessment.Limitations, "configured default") {
			t.Fatalf("the configured-baseline limitation is missing: %v", pkg.TechnicalAssessment.Limitations)
		}
	})

	t.Run("no configured default yields a package without a baseline", func(t *testing.T) {
		pkg, err := (Composer{}).Compose(
			context.Background(), noSeverityStage0(), goodAssessment(), completeValidation(), nil)
		if err != nil {
			t.Fatalf("a ticket without severity must still deliver a human package: %v", err)
		}
		if pkg.MachineDisposition.Baseline != nil {
			t.Fatalf("no severity source must leave the baseline absent: %+v", pkg.MachineDisposition.Baseline)
		}
	})

	t.Run("advisory severity beats the configured default", func(t *testing.T) {
		pkg, err := (Composer{DefaultBaselineSeverity: "LOW"}).Compose(
			context.Background(), goodStage0(), goodAssessment(), completeValidation(), nil)
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		if pkg.MachineDisposition.Baseline.Severity != "HIGH" || pkg.MachineDisposition.Baseline.Source == "config:baseline.default_severity" {
			t.Fatalf("derived baseline must win over the configured default: %+v", pkg.MachineDisposition.Baseline)
		}
		if hasLimitationContaining(pkg.TechnicalAssessment.Limitations, "configured default") {
			t.Fatal("no default-fallback limitation may appear when severity is derived")
		}
	})

	t.Run("UNKNOWN default yields a consistent P2 package", func(t *testing.T) {
		pkg, err := (Composer{DefaultBaselineSeverity: "UNKNOWN"}).Compose(
			context.Background(), noSeverityStage0(), goodAssessment(), completeValidation(), nil)
		if err != nil {
			t.Fatalf("Compose with UNKNOWN default must succeed: %v", err)
		}
		if pkg.MachineDisposition.Baseline.Severity != "UNKNOWN" || pkg.MachineDisposition.Baseline.Priority != string(domain.PriorityP2) {
			t.Fatalf("UNKNOWN default must give nominal P2: %+v", pkg.MachineDisposition.Baseline)
		}
	})

	t.Run("unvalidated configured value is ignored fail-closed", func(t *testing.T) {
		// A value that could not pass site validation must never synthesize
		// a baseline — it is ignored exactly like an unset default.
		pkg, err := (Composer{DefaultBaselineSeverity: "severe"}).Compose(
			context.Background(), noSeverityStage0(), goodAssessment(), completeValidation(), nil)
		if err != nil {
			t.Fatalf("an invalid configured severity must not fail the human result: %v", err)
		}
		if pkg.MachineDisposition.Baseline != nil {
			t.Fatalf("an invalid configured severity must not become a baseline: %+v", pkg.MachineDisposition.Baseline)
		}
	})
}

// TestDemotionRules covers the demotion contract: DISMISSED/LOWERED are
// unreachable while any decision-relevant fact or check is short of
// verified.
func TestDemotionRules(t *testing.T) {
	dismissedStage0 := func() Stage0Result {
		s0 := goodStage0()
		s0.PackageCheck = PackageCheckResult{
			Class: CheckModuleAbsent, ClaimedPath: "example.org/library",
			EvidenceSource: "module_graph", Provenance: []string{"go list -m all"},
		}
		return s0
	}
	passChecks := func() []CheckResult {
		out := make([]CheckResult, 0, len(prePackageCheckIDs))
		for _, id := range prePackageCheckIDs {
			out = append(out, CheckResult{ID: id, Status: CheckPass})
		}
		return out
	}

	cases := []struct {
		name   string
		checks []CheckResult
		mutate func(*Stage0Result, *Assessment, *FactValidation)
	}{
		{
			name:   "unreferenced claim evidence blocks dismissal",
			checks: passChecks(),
			mutate: func(_ *Stage0Result, _ *Assessment, fv *FactValidation) {
				fv.Status = ValidationPartial
				fv.References = append(fv.References, ReferenceCheck{
					Subject: "c1", Status: FactUnreferenced, Effect: EffectBlocksRiskReduction,
				})
			},
		},
		{
			name:   "conflicting evidence blocks dismissal",
			checks: passChecks(),
			mutate: func(_ *Stage0Result, _ *Assessment, fv *FactValidation) {
				fv.Status = ValidationFailed
				fv.References = append(fv.References, ReferenceCheck{
					EvidenceID: "ev-1", Status: FactConflicting, Effect: EffectBlocksRiskReduction,
				})
			},
		},
		{
			name:   "unverified intake field blocks dismissal",
			checks: passChecks(),
			mutate: func(s0 *Stage0Result, _ *Assessment, _ *FactValidation) {
				s0.Validation.Fields = append(s0.Validation.Fields, FieldValidation{
					Field: "vulnerability_ids", Status: IntakeUnverified, BlocksRiskReduction: true,
				})
			},
		},
		{
			name:   "one unverified check blocks dismissal",
			checks: replaceCheck(passChecks(), CheckIDPackageVersion, CheckUnverified),
			mutate: func(*Stage0Result, *Assessment, *FactValidation) {},
		},
		{
			name:   "unknown check status fails closed",
			checks: replaceCheck(passChecks(), CheckIDEvidenceReferences, CheckStatus("BOGUS")),
			mutate: func(*Stage0Result, *Assessment, *FactValidation) {},
		},
		{
			name:   "missing check fails closed",
			checks: passChecks()[:len(passChecks())-1],
			mutate: func(*Stage0Result, *Assessment, *FactValidation) {},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s0 := dismissedStage0()
			a := goodAssessment()
			fv := completeValidation()
			tc.mutate(&s0, &a, &fv)
			pkg, err := ComposeDecision(context.Background(), s0, a, fv, tc.checks, nil)
			if err != nil {
				t.Fatalf("ComposeDecision: %v", err)
			}
			if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
				t.Fatalf("recommendation = %s, want UNCHANGED", pkg.MachineDisposition.Recommendation)
			}
			if len(pkg.MachineDisposition.Demotions) == 0 {
				t.Fatal("demotion must be recorded")
			}
			// Support is the human axis and never follows the machine
			// demotion; the withheld reduction is visible in the machine
			// policy outcome instead, which can never ALLOW it.
			if pkg.MachineDisposition.Automation == AutomationAllow {
				t.Fatal("a demoted machine disposition must never be reported as an admitted reduction")
			}
		})
	}

	t.Run("integrity conflict is an error not UNCHANGED", func(t *testing.T) {
		s0 := dismissedStage0()
		s0.Snapshot.InputHash = "tampered"

		// Auto-run path: the composer computes the checks itself.
		if _, err := ComposeDecision(context.Background(), s0, goodAssessment(), completeValidation(), nil, nil); err == nil {
			t.Fatal("C01 integrity conflict (auto-run) must be a technical error")
		}
		// Caller-supplied path: an injected CONFLICTING on an integrity
		// check is an error as well.
		checks := replaceCheck(passChecks(), CheckIDIntakeIdentity, CheckConflicting)
		if _, err := ComposeDecision(context.Background(), dismissedStage0(), goodAssessment(), completeValidation(), checks, nil); err == nil {
			t.Fatal("C01 integrity conflict (supplied) must be a technical error")
		}
	})

	t.Run("check error is an error not UNCHANGED", func(t *testing.T) {
		checks := replaceCheck(passChecks(), CheckIDSnapshotIntegrity, CheckError)
		_, err := ComposeDecision(context.Background(), dismissedStage0(), goodAssessment(), completeValidation(), checks, nil)
		if err == nil {
			t.Fatal("check ERROR must be a technical error")
		}
	})
}

// TestComposerNoBaselineEscalation: the composer never produces a stronger
// disposition than the baseline permits, and a human proposal that asks for
// a dismissal never becomes one.
func TestComposerNoBaselineEscalation(t *testing.T) {
	a := goodAssessment()
	a.ProposedAction.Kind = HumanActionClose
	a.ProposedAction.Instruction = "dismiss everything"
	pkg := composeOrFail(t, goodStage0(), a, completeValidation())
	if pkg.MachineDisposition.Recommendation != RecommendationLowered {
		t.Fatalf("recommendation = %s", pkg.MachineDisposition.Recommendation)
	}
	if pkg.MachineDisposition.Baseline.Priority == "" || pkg.MachineDisposition.Baseline.Priority == "DISMISSED" {
		t.Fatalf("baseline priority wrong: %q", pkg.MachineDisposition.Baseline.Priority)
	}
}

// TestComposerProviderFailure: a provider error is a limitation plus
// demotion — never a fabricated fact and never silently ignored.
func TestComposerProviderFailure(t *testing.T) {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{
		Class: CheckModuleAbsent, ClaimedPath: "example.org/library",
		EvidenceSource: "module_graph", Provenance: []string{"go list -m all"},
	}
	failing := failingProvider{}
	pkg, err := ComposeDecision(context.Background(), s0, goodAssessment(), completeValidation(), nil,
		[]FactProvider{Stage0FactsProvider{}, PackageFactsProvider{}, failing})
	if err != nil {
		t.Fatalf("ComposeDecision: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("provider failure must demote to UNCHANGED, got %s", pkg.MachineDisposition.Recommendation)
	}
	found := false
	for _, f := range pkg.Facts {
		if f.Kind == FactProviderError && f.Status == ObsUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatal("provider failure must leave an UNAVAILABLE provider fact")
	}
}

type failingProvider struct{}

func (failingProvider) Name() string { return "failing" }
func (failingProvider) Collect(context.Context, ProviderInput) ([]DecisionFact, error) {
	return nil, errProviderBroke
}

var errProviderBroke = errTest("provider broke")

type errTest string

func (e errTest) Error() string { return string(e) }

// TestComposerAuditBinding: identity, hashes and provenance of the package
// bind to input, config, ref, commit, snapshot, advisory, toolchain and
// the recorded prompt — spec constraint 7.
func TestComposerAuditBinding(t *testing.T) {
	s0 := goodStage0()
	pkg := composeOrFail(t, s0, goodAssessment(), completeValidation())
	au := pkg.Audit
	if au.TicketHash != s0.Raw.TicketHash || au.ConfigHash != s0.ConfigHash {
		t.Fatalf("audit identity fields wrong: %+v", au)
	}
	if au.SelectedRef != "v1.4.0" || au.ResolvedCommit != strings.Repeat("ab", 20) {
		t.Fatalf("audit ref/commit wrong: %+v", au)
	}
	if au.SnapshotHash != s0.Snapshot.ContentHash || au.AdvisoryHash != s0.Advisory.SHA256 {
		t.Fatalf("audit snapshot/advisory hashes wrong: %+v", au)
	}
	if au.Toolchain.ReleaseVersion != "1.25.8" || au.Toolchain.Version != "1.25.8" {
		t.Fatalf("audit toolchain wrong: %+v", au.Toolchain)
	}
	if au.PromptHash != strings.Repeat("09", 32) {
		t.Fatalf("audit prompt_hash must come from the agent run, got %q", au.PromptHash)
	}
	if au.Stage0.InputHash != s0.Input.SHA256 || au.Stage0.SourceID != "service-example" {
		t.Fatalf("stage0 provenance wrong: %+v", au.Stage0)
	}
	if pkg.ExecutionMode != "ci" {
		t.Fatalf("execution mode = %q, want ci", pkg.ExecutionMode)
	}
	if pkg.Judgment.Verdict != VerdictNotExploitable || pkg.Judgment.Summary != "vulnerable code is not reachable in this build" {
		t.Fatalf("the recorded judgment must travel verbatim: %+v", pkg.Judgment)
	}
}

// TestComposerLimitsBindBudget pins the provenance contract for the
// effective budgets: Composer.Limits lands verbatim in audit.limits and
// changing it — e.g. max_output_tokens between stability retries — changes
// the canonical package hash, so replay's drift check can never call two
// differently-budgeted packages identical.
func TestComposerLimitsBindBudget(t *testing.T) {
	s0 := goodStage0()
	a := goodAssessment()
	fv := completeValidation()

	base := Composer{Limits: BudgetConfig{MaxLLMSteps: 8, MaxToolCalls: 64, MaxSourceBytes: 1 << 20, TimeoutSeconds: 600, MaxOutputTokens: 16000}}
	pkgBase, err := base.Compose(context.Background(), s0, a, fv, nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkgBase.Audit.Limits.MaxOutputTokens != 16000 {
		t.Fatalf("audit.limits.max_output_tokens = %d, want 16000", pkgBase.Audit.Limits.MaxOutputTokens)
	}

	other := base
	other.Limits.MaxOutputTokens = 32000
	pkgOther, err := other.Compose(context.Background(), s0, a, fv, nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkgOther.Audit.Limits.MaxOutputTokens != 32000 {
		t.Fatalf("audit.limits.max_output_tokens = %d, want 32000", pkgOther.Audit.Limits.MaxOutputTokens)
	}
	if canonicalDecisionHash(pkgBase) == canonicalDecisionHash(pkgOther) {
		t.Fatal("decision hash must change when the recorded output budget changes; replay drift would be blind to it")
	}
}

func TestComposerDemotesUnstableVerifiedProof(t *testing.T) {
	verified := stabilityProofReport(FalsifierVerified)
	a := assessmentWithProposal(goodAssessment(), declaredProofProposal("fp-stability", "c1", "cond-1"))
	stable, err := (Composer{}).ComposeWithEvidence(context.Background(), dismissedForStability(), a, completeValidation(), EvidenceInput{Falsifiers: &verified})
	if err != nil {
		t.Fatalf("stable compose: %v", err)
	}
	if stable.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("stable verified proof = %s, want DISMISSED", stable.MachineDisposition.Recommendation)
	}
	attempts := attemptSeries(2)
	attempts[0].Recommendation, attempts[0].FalsifierHash = RecommendationDismissed, "proof-stable"
	attempts[1].Recommendation, attempts[1].FalsifierHash = RecommendationUnchanged, "proof-unstable"
	stability := CheckStability(attempts)
	unstable, err := (Composer{Stability: &stability}).ComposeWithEvidence(context.Background(), dismissedForStability(), a, completeValidation(), EvidenceInput{Falsifiers: &verified})
	if err != nil {
		t.Fatalf("unstable compose: %v", err)
	}
	if unstable.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("unstable verified proof = %s, want UNCHANGED", unstable.MachineDisposition.Recommendation)
	}
	found := false
	for _, text := range unstable.MachineDisposition.Demotions {
		if strings.Contains(text, "stability") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unstable proof has no stability demotion: %v", unstable.MachineDisposition.Demotions)
	}
}

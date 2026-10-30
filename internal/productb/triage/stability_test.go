package triage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/evidencetools"
)

// stableAttempt is a fully populated canonical attempt projection: every
// semantic field (recommendation, profile, decisive facts, support,
// readiness, policy outcome, assumption/trigger hashes) and every
// provenance pin (input, snapshot, advisory, config, ruleset, prompt,
// toolchain, selected ref, resolved commit) is set, so a single-field
// mutation is always detectable.
func stableAttempt() StabilityAttempt {
	return StabilityAttempt{
		Attempt:              1,
		Judgment:             string(VerdictInconclusive),
		JudgmentHash:         strings.Repeat("0a", 32),
		ActionKind:           string(HumanActionKeepOpen),
		ActionScope:          "captured product snapshot",
		ActionHash:           strings.Repeat("0b", 32),
		PremisesSemanticHash: strings.Repeat("0c", 32),
		PremisesHash:         strings.Repeat("1c", 32),
		SupportLevel:         string(SupportLevelSubstantiated),
		SupportSemanticHash:  strings.Repeat("0d", 32),
		SupportHash:          strings.Repeat("1d", 32),
		Recommendation:       RecommendationUnchanged,
		MachineHash:          strings.Repeat("0e", 32),
		ProfileID:            "baseline-fallback",
		Readiness:            "READY_WITH_LIMITATIONS",
		PolicyOutcome:        "WARN",
		DecisiveFacts:        []string{"fact-component=SUPPORTS", "fact-presence=REFUTES"},
		SelectedRef:          "v1.4.0",
		ResolvedCommit:       strings.Repeat("ab", 20),
		AssumptionsHash:      strings.Repeat("01", 32),
		TriggersHash:         strings.Repeat("02", 32),
		InputHash:            strings.Repeat("03", 32),
		SnapshotHash:         strings.Repeat("04", 32),
		AdvisoryHash:         strings.Repeat("05", 32),
		ConfigHash:           strings.Repeat("06", 32),
		RuleSetHash:          strings.Repeat("07", 32),
		PromptHash:           strings.Repeat("08", 32),
		ToolchainHash:        strings.Repeat("09", 32),
	}
}

func attemptSeries(n int) []StabilityAttempt {
	out := make([]StabilityAttempt, n)
	for i := range out {
		out[i] = stableAttempt()
		out[i].Attempt = i + 1
	}
	return out
}

// TestStabilityIdenticalAttempts: retries that reproduce the same decision
// surface on the same provenance are stable — the report changes nothing.
func TestStabilityIdenticalAttempts(t *testing.T) {
	report := CheckStability(attemptSeries(3))
	if !report.Stable {
		t.Fatalf("identical attempts reported unstable: %v", report.Limitations)
	}
	if report.Drift {
		t.Fatalf("identical attempts reported drift: %v", report.Limitations)
	}
	if report.Retries != 2 || len(report.Attempts) != 3 {
		t.Fatalf("report shape wrong: retries=%d attempts=%d", report.Retries, len(report.Attempts))
	}
	if len(report.Limitations) != 0 {
		t.Fatalf("stable run recorded limitations: %v", report.Limitations)
	}
}

// TestStabilitySemanticDiffs: a change in any canonical decision field is
// semantic instability — never provenance drift.
func TestStabilitySemanticDiffs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*StabilityAttempt)
	}{
		{"judgment", func(a *StabilityAttempt) { a.Judgment = string(VerdictNotExploitable) }},
		{"judgment text", func(a *StabilityAttempt) { a.JudgmentHash = strings.Repeat("1a", 32) }},
		{"action kind", func(a *StabilityAttempt) { a.ActionKind = string(HumanActionClose) }},
		{"action scope", func(a *StabilityAttempt) { a.ActionScope = "another product build" }},
		{"action text", func(a *StabilityAttempt) { a.ActionHash = strings.Repeat("1b", 32) }},
		{"premise semantics", func(a *StabilityAttempt) { a.PremisesSemanticHash = strings.Repeat("1c", 32) }},
		{"support level", func(a *StabilityAttempt) { a.SupportLevel = string(SupportLevelLimited) }},
		{"support representation", func(a *StabilityAttempt) { a.SupportSemanticHash = strings.Repeat("1d", 32) }},
		{"recommendation", func(a *StabilityAttempt) { a.Recommendation = RecommendationDismissed }},
		{"machine disposition", func(a *StabilityAttempt) { a.MachineHash = strings.Repeat("1e", 32) }},
		{"profile", func(a *StabilityAttempt) { a.ProfileID = "internal-service" }},
		{"decisive fact status", func(a *StabilityAttempt) {
			a.DecisiveFacts[1] = "fact-presence=SUPPORTS"
		}},
		{"decisive fact order", func(a *StabilityAttempt) {
			a.DecisiveFacts[0], a.DecisiveFacts[1] = a.DecisiveFacts[1], a.DecisiveFacts[0]
		}},
		{"readiness", func(a *StabilityAttempt) { a.Readiness = "READY" }},
		{"policy outcome", func(a *StabilityAttempt) { a.PolicyOutcome = "ALLOW" }},
		{"assumptions hash", func(a *StabilityAttempt) { a.AssumptionsHash = strings.Repeat("10", 32) }},
		{"triggers hash", func(a *StabilityAttempt) { a.TriggersHash = strings.Repeat("20", 32) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attempts := attemptSeries(2)
			tc.mutate(&attempts[1])
			report := CheckStability(attempts)
			if report.Stable {
				t.Fatalf("changed %s reported stable", tc.name)
			}
			if report.Drift {
				t.Fatalf("semantic change in %s misclassified as provenance drift", tc.name)
			}
			if report.Retries != 1 {
				t.Fatalf("retries = %d, want 1", report.Retries)
			}
			if len(report.Limitations) == 0 {
				t.Fatal("unstable report records no reason")
			}
		})
	}
}

// TestStabilityComparesHumanAndMachineAxes: the comparison reports the
// human decision surface (judgment, proposed action, decisive premises,
// support) and the machine reduction as separate axes. A change on one axis
// never masquerades as a change on the other, provenance drift stays a
// technical error, every attempt is retained verbatim and no attempt is
// selected as the better answer.
func TestStabilityComparesHumanAndMachineAxes(t *testing.T) {
	pkg := composeOrFail(t, dismissedForStability(), goodAssessment(), completeValidation())
	base := ProjectStabilityAttempt(1, pkg)

	t.Run("human axis divergence", func(t *testing.T) {
		human := ProjectStabilityAttempt(2, pkg)
		human.Judgment = string(VerdictInconclusive)
		if human.Judgment == base.Judgment {
			human.Judgment = string(VerdictExploitable)
		}
		human.JudgmentHash = strings.Repeat("aa", 32)
		human.ActionKind = string(HumanActionKeepOpen)
		human.ActionScope = "a different captured build"
		human.PremisesSemanticHash = strings.Repeat("bb", 32)
		human.SupportLevel = string(SupportLevelSubstantiated)
		if human.SupportLevel == base.SupportLevel {
			human.SupportLevel = string(SupportLevelLimited)
		}
		human.SupportSemanticHash = strings.Repeat("cc", 32)
		report := CheckStability([]StabilityAttempt{base, human})
		if report.Stable || report.Drift {
			t.Fatalf("human divergence = %+v, want unstable without drift", report)
		}
		for _, field := range []string{"judgment", "action_kind", "premises_semantics", "support_level"} {
			if !limitationNames(t, report.Limitations, "human "+field) {
				t.Fatalf("human divergence did not name %q: %v", field, report.Limitations)
			}
		}
		for _, l := range report.Limitations {
			if strings.Contains(l, "machine ") {
				t.Fatalf("human divergence leaked into the machine axis: %q", l)
			}
		}
	})

	t.Run("attempt-local identity is audit-only", func(t *testing.T) {
		// The exact premise/support hashes record attempt-local identity
		// (observation ids, payload digests, support diagnostics). They are
		// kept for audit and must not be compared: retries intentionally
		// rename attempt-scoped observations.
		auditOnly := ProjectStabilityAttempt(2, pkg)
		auditOnly.PremisesHash = strings.Repeat("fa", 32)
		auditOnly.SupportHash = strings.Repeat("fb", 32)
		report := CheckStability([]StabilityAttempt{base, auditOnly})
		if !report.Stable || report.Drift {
			t.Fatalf("exact identity hashes decided stability: %+v", report)
		}
		if len(report.Limitations) != 0 {
			t.Fatalf("audit-only hashes produced a limitation: %v", report.Limitations)
		}
	})

	t.Run("machine axis divergence", func(t *testing.T) {
		machine := ProjectStabilityAttempt(2, pkg)
		machine.Recommendation = RecommendationUnchanged
		machine.MachineHash = strings.Repeat("dd", 32)
		machine.PolicyOutcome = string(AutomationWarn)
		report := CheckStability([]StabilityAttempt{base, machine})
		if report.Stable || report.Drift {
			t.Fatalf("machine divergence = %+v, want unstable without drift", report)
		}
		for _, field := range []string{"recommendation", "machine_disposition_hash", "policy_outcome"} {
			if !limitationNames(t, report.Limitations, "machine "+field) {
				t.Fatalf("machine divergence did not name %q: %v", field, report.Limitations)
			}
		}
		for _, l := range report.Limitations {
			if strings.Contains(l, "human ") {
				t.Fatalf("machine divergence leaked into the human axis: %q", l)
			}
		}
	})

	t.Run("provenance drift is not a semantic axis", func(t *testing.T) {
		drifted := ProjectStabilityAttempt(2, pkg)
		drifted.SnapshotHash = strings.Repeat("ee", 32)
		report := CheckStability([]StabilityAttempt{base, drifted})
		if !report.Drift || !report.Stable {
			t.Fatalf("provenance change = %+v, want drift with stable semantics", report)
		}
	})

	t.Run("every attempt is retained without best-of selection", func(t *testing.T) {
		// Attempt 1 is the weaker machine result; attempt 2 is the
		// reduction the rules would prefer. Neither may be selected or
		// reordered: instability is recorded, not resolved.
		first := ProjectStabilityAttempt(1, pkg)
		second := ProjectStabilityAttempt(2, pkg)
		first.Recommendation = RecommendationUnchanged
		second.Recommendation = RecommendationDismissed
		report := CheckStability([]StabilityAttempt{first, second})
		if report.Stable {
			t.Fatal("disagreeing attempts reported stable")
		}
		if report.Retries != 1 || len(report.Attempts) != 2 {
			t.Fatalf("attempt series not retained: %+v", report)
		}
		if report.Attempts[0].Attempt != 1 || report.Attempts[0].Recommendation != RecommendationUnchanged ||
			report.Attempts[1].Attempt != 2 || report.Attempts[1].Recommendation != RecommendationDismissed {
			t.Fatalf("CheckStability reordered or rewrote the recorded attempts: %+v", report.Attempts)
		}
		if report.SelectedAttempt != 0 {
			t.Fatalf("the comparison invented a selected attempt %d; selection belongs to the recorded run", report.SelectedAttempt)
		}
	})
}

// limitationNames reports whether one limitation line names the given
// field with its axis label.
func limitationNames(t *testing.T, limitations []string, want string) bool {
	t.Helper()
	for _, l := range limitations {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

// attemptArchive is one independently composed attempt: its package plus the
// recorded assessment, validation and observation it was composed from, so a
// stability report can be fed back into a second composition.
type attemptArchive struct {
	pkg         DecisionPackage
	assessment  Assessment
	validation  FactValidation
	observation RecordedObservation
}

// composeAttemptArchive composes one attempt's package against its own
// attempt-qualified observation archive, the way the live retry path does:
// the store mints det-0001 for the primary attempt and det-a2-0001 for
// retry 2, and the assessment cites that attempt's locator.
func composeAttemptArchive(t *testing.T, attempt int, fact string) attemptArchive {
	t.Helper()
	s0 := dismissedForStability()
	obsID := observationID("det", 1, NewObservationStore(attempt))
	observation := supportObservation(t, s0, obsID, fact, attempt)
	assessment := supportAssessment(
		[]EvidenceRef{{ID: "ev-1", Kind: "observation", Locator: "det:" + obsID}},
		[]Claim{measuredObservationClaim("c1", fact, "ev-1")},
		nil,
		"c1",
	)
	// A negative judgment lets the deterministic dismissal rule stand; the
	// stability comparison then decides whether the retry series keeps it.
	assessment.Verdict = VerdictNotExploitable
	assessment.Audit = &AssessmentAudit{PromptHash: strings.Repeat("09", 32)}
	validation := supportValidation(s0.Snapshot.ContentHash, "ev-1")
	pkg, err := (Composer{RulesetHash: strings.Repeat("07", 32)}).ComposeWithEvidence(
		context.Background(), s0, assessment, validation,
		EvidenceInput{Observations: []RecordedObservation{observation}, SelectedAttempt: attempt},
	)
	if err != nil {
		t.Fatalf("compose attempt %d: %v", attempt, err)
	}
	return attemptArchive{pkg: pkg, assessment: assessment, validation: validation, observation: observation}
}

// TestStabilityAttemptQualifiedObservationIDsStable: two independently
// composed attempts that establish the same proposition against their own
// attempt-qualified archives (det-0001 vs det-a2-0001) are semantically
// stable. The exact premise hash records the attempt-local ids for audit,
// but the compared semantic projection ignores them, so the retry series
// keeps its support and the reduction the rules permit.
func TestStabilityAttemptQualifiedObservationIDsStable(t *testing.T) {
	fact := "module example.org/library is absent from the recorded build graph"
	first := composeAttemptArchive(t, 1, fact)
	second := composeAttemptArchive(t, 2, fact)
	firstID := observationID("det", 1, NewObservationStore(1))
	secondID := observationID("det", 1, NewObservationStore(2))
	if firstID == secondID {
		t.Fatalf("fixture did not produce attempt-qualified ids: %q == %q", firstID, secondID)
	}
	if first.pkg.ProposedAction.Kind != HumanActionClose || second.pkg.ProposedAction.Kind != HumanActionClose {
		t.Fatalf("fixture actions = %s / %s", first.pkg.ProposedAction.Kind, second.pkg.ProposedAction.Kind)
	}
	if first.pkg.Support.Level != SupportLevelSubstantiated || second.pkg.Support.Level != SupportLevelSubstantiated {
		t.Fatalf("fixture support = %s / %s, want SUBSTANTIATED", first.pkg.Support.Level, second.pkg.Support.Level)
	}
	if first.pkg.MachineDisposition.Recommendation != RecommendationDismissed ||
		second.pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("fixture recommendations = %s / %s, want DISMISSED",
			first.pkg.MachineDisposition.Recommendation, second.pkg.MachineDisposition.Recommendation)
	}
	// The fixtures really do cite their own attempt-local observation id in
	// the recorded premises — otherwise the regression is not exercised.
	found := func(pkg DecisionPackage, want string) bool {
		for _, pr := range pkg.Premises {
			for _, ref := range pr.SourceRefs {
				if ref == "det:"+want {
					return true
				}
			}
		}
		return false
	}
	if !found(first.pkg, firstID) || !found(second.pkg, secondID) {
		t.Fatalf("fixtures do not cite their attempt-local observations %q / %q", firstID, secondID)
	}

	firstAttempt := ProjectStabilityAttempt(1, first.pkg)
	secondAttempt := ProjectStabilityAttempt(2, second.pkg)
	if firstAttempt.PremisesHash == secondAttempt.PremisesHash {
		t.Fatal("exact premise hashes did not record the attempt-local identity difference")
	}
	if firstAttempt.PremisesSemanticHash != secondAttempt.PremisesSemanticHash {
		t.Fatalf("semantic premise projection depends on attempt-local ids: %s != %s",
			firstAttempt.PremisesSemanticHash, secondAttempt.PremisesSemanticHash)
	}
	if firstAttempt.SupportSemanticHash != secondAttempt.SupportSemanticHash {
		t.Fatalf("semantic support projection differs: %s != %s",
			firstAttempt.SupportSemanticHash, secondAttempt.SupportSemanticHash)
	}

	report := CheckStability([]StabilityAttempt{firstAttempt, secondAttempt})
	if !report.Stable || report.Drift {
		t.Fatalf("equivalent attempt-qualified retries reported unstable: %+v", report)
	}
	if len(report.Limitations) != 0 {
		t.Fatalf("equivalent attempt-qualified retries recorded limitations: %v", report.Limitations)
	}

	// The stable verdict must neither cap support nor withhold the
	// otherwise admissible reduction.
	withReport, err := (Composer{RulesetHash: strings.Repeat("07", 32), Stability: &report}).ComposeWithEvidence(
		context.Background(), dismissedForStability(), second.assessment, second.validation,
		EvidenceInput{Observations: []RecordedObservation{second.observation}, SelectedAttempt: 2},
	)
	if err != nil {
		t.Fatalf("compose with stability report: %v", err)
	}
	if withReport.TechnicalAssessment.StabilityResult != "stable" {
		t.Fatalf("stability_result = %q, want stable", withReport.TechnicalAssessment.StabilityResult)
	}
	if withReport.Support.Level != SupportLevelSubstantiated {
		t.Fatalf("support capped by attempt-local identity: %s (%v)", withReport.Support.Level, withReport.Support.Reasons)
	}
	if withReport.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("reduction withheld by attempt-local identity: %s", withReport.MachineDisposition.Recommendation)
	}
}

// TestStabilityGenuineSemanticDifferenceDetected: attempts that establish
// different propositions still disagree — the semantic projection removes
// attempt-local identity, not meaning.
func TestStabilityGenuineSemanticDifferenceDetected(t *testing.T) {
	absent := composeAttemptArchive(t, 1, "module example.org/library is absent from the recorded build graph")
	present := composeAttemptArchive(t, 2, "module example.org/library is present in the recorded build graph")
	absentAttempt := ProjectStabilityAttempt(1, absent.pkg)
	presentAttempt := ProjectStabilityAttempt(2, present.pkg)
	if absentAttempt.PremisesSemanticHash == presentAttempt.PremisesSemanticHash {
		t.Fatal("a genuine proposition difference collapsed into the same semantic premise projection")
	}
	report := CheckStability([]StabilityAttempt{absentAttempt, presentAttempt})
	if report.Stable {
		t.Fatalf("genuine semantic difference reported stable: %+v", report)
	}
	if report.Drift {
		t.Fatalf("genuine semantic difference misclassified as provenance drift: %+v", report)
	}
	if !limitationNames(t, report.Limitations, "human premises_semantics") {
		t.Fatalf("semantic divergence was not reported on the premise axis: %v", report.Limitations)
	}
}

// TestStabilityOwnerOnlyDivergence: changing the owner of an assumed premise
// is a semantic change on the human axis even when every proposition, basis,
// dependency edge and the support level stay identical.
func TestStabilityOwnerOnlyDivergence(t *testing.T) {
	pkg := actionCardFixture(t)
	changed := pkg
	changed.Premises = append([]DecisionPremise(nil), pkg.Premises...)
	owned := false
	for i := range changed.Premises {
		if changed.Premises[i].Basis != PremiseAssumed {
			continue
		}
		if changed.Premises[i].Owner == "" {
			t.Fatalf("assumed premise %q carries no owner to change", changed.Premises[i].ClaimID)
		}
		changed.Premises[i].Owner = "platform-team"
		owned = true
	}
	if !owned {
		t.Fatal("fixture carries no assumed premise")
	}
	base := ProjectStabilityAttempt(1, pkg)
	other := ProjectStabilityAttempt(2, changed)
	if base.PremisesSemanticHash == other.PremisesSemanticHash {
		t.Fatal("an owner-only change collapsed into the same semantic premise projection")
	}
	if base.SupportSemanticHash != other.SupportSemanticHash || base.SupportLevel != other.SupportLevel {
		t.Fatalf("owner-only fixture changed the support axis: %+v -> %+v", base, other)
	}
	report := CheckStability([]StabilityAttempt{base, other})
	if report.Stable {
		t.Fatalf("owner-only divergence reported stable: %+v", report)
	}
	if report.Drift {
		t.Fatalf("owner-only divergence misclassified as provenance drift: %+v", report)
	}
	if !limitationNames(t, report.Limitations, "human premises_semantics") {
		t.Fatalf("owner divergence was not reported on the premise axis: %v", report.Limitations)
	}
}

// TestStabilityDependencyEdgeOnlyDivergence: changing a dependency edge is a
// semantic change even when the decisive closure, every premise body/basis
// and the support level are identical.
func TestStabilityDependencyEdgeOnlyDivergence(t *testing.T) {
	pkg := actionCardFixture(t)
	changed := pkg
	changed.Premises = append([]DecisionPremise(nil), pkg.Premises...)
	edgeChanged := false
	for i := range changed.Premises {
		pr := &changed.Premises[i]
		if len(pr.DependsOn) == 0 {
			continue
		}
		existing := make(map[string]bool, len(pr.DependsOn)+1)
		existing[pr.ClaimID] = true
		for _, dep := range pr.DependsOn {
			existing[dep] = true
		}
		// Add one edge to another premise already in the decisive closure:
		// the closure, statements, bases and support stay untouched.
		var extra string
		for _, candidate := range changed.Premises {
			if !existing[candidate.ClaimID] {
				extra = candidate.ClaimID
				break
			}
		}
		if extra == "" {
			continue
		}
		pr.DependsOn = append(append([]string(nil), pr.DependsOn...), extra)
		edgeChanged = true
		break
	}
	if !edgeChanged {
		t.Fatal("fixture carries no dependency edge to change")
	}
	base := ProjectStabilityAttempt(1, pkg)
	other := ProjectStabilityAttempt(2, changed)
	if base.PremisesSemanticHash == other.PremisesSemanticHash {
		t.Fatal("an edge-only change collapsed into the same semantic premise projection")
	}
	if base.SupportSemanticHash != other.SupportSemanticHash || base.SupportLevel != other.SupportLevel {
		t.Fatalf("edge-only fixture changed the support axis: %+v -> %+v", base, other)
	}
	report := CheckStability([]StabilityAttempt{base, other})
	if report.Stable {
		t.Fatalf("edge-only divergence reported stable: %+v", report)
	}
	if report.Drift {
		t.Fatalf("edge-only divergence misclassified as provenance drift: %+v", report)
	}
	if !limitationNames(t, report.Limitations, "human premises_semantics") {
		t.Fatalf("edge divergence was not reported on the premise axis: %v", report.Limitations)
	}
}

// TestDriftProvenanceFields: any change in a pinned input — snapshot,
// config, advisory, selected ref, resolved commit, toolchain, ruleset,
// prompt or input hash — between attempts is provenance drift, and drift
// is never counted as semantic instability.
func TestDriftProvenanceFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*StabilityAttempt)
	}{
		{"snapshot_hash", func(a *StabilityAttempt) { a.SnapshotHash = strings.Repeat("14", 32) }},
		{"config_hash", func(a *StabilityAttempt) { a.ConfigHash = strings.Repeat("16", 32) }},
		{"advisory_hash", func(a *StabilityAttempt) { a.AdvisoryHash = strings.Repeat("15", 32) }},
		{"input_hash", func(a *StabilityAttempt) { a.InputHash = strings.Repeat("13", 32) }},
		{"ruleset_hash", func(a *StabilityAttempt) { a.RuleSetHash = strings.Repeat("17", 32) }},
		{"prompt_hash", func(a *StabilityAttempt) { a.PromptHash = strings.Repeat("18", 32) }},
		{"toolchain_hash", func(a *StabilityAttempt) { a.ToolchainHash = strings.Repeat("19", 32) }},
		{"selected_ref", func(a *StabilityAttempt) { a.SelectedRef = "v9.9.9" }},
		{"resolved_commit", func(a *StabilityAttempt) { a.ResolvedCommit = strings.Repeat("cd", 20) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attempts := attemptSeries(2)
			tc.mutate(&attempts[1])
			report := CheckStability(attempts)
			if !report.Drift {
				t.Fatalf("changed %s not detected as provenance drift", tc.name)
			}
			if !report.Stable {
				t.Fatalf("pure provenance drift in %s must not be counted as semantic instability", tc.name)
			}
			found := false
			for _, l := range report.Limitations {
				if strings.Contains(l, tc.name) {
					found = true
				}
			}
			if !found {
				t.Fatalf("limitations do not name the drifted field %s: %v", tc.name, report.Limitations)
			}
		})
	}
}

// TestDriftWithSemanticDiff: when provenance and semantics both diverge,
// drift still wins — it is a technical error channel, not instability.
func TestDriftWithSemanticDiff(t *testing.T) {
	attempts := attemptSeries(2)
	attempts[1].SnapshotHash = strings.Repeat("14", 32)
	attempts[1].Recommendation = RecommendationLowered
	report := CheckStability(attempts)
	if !report.Drift {
		t.Fatal("provenance change not flagged as drift")
	}
	if report.Stable {
		t.Fatal("semantic change alongside drift must still be recorded")
	}
}

// TestStabilityNoRetries: without extra attempts there is nothing to
// disagree with — a single run is trivially stable and records no retries.
func TestStabilityNoRetries(t *testing.T) {
	report := CheckStability(attemptSeries(1))
	if !report.Stable || report.Drift || report.Retries != 0 {
		t.Fatalf("single attempt should be stable without retries: %+v", report)
	}
	report = CheckStability(nil)
	if !report.Stable || report.Drift || report.Retries != 0 {
		t.Fatalf("empty attempt set should be stable without retries: %+v", report)
	}
}

// dismissedForStability is the clean Stage 0 fixture whose module-absence
// package check makes the dismissal rule fire — the candidate the
// composer would emit without a stability report.
func dismissedForStability() Stage0Result {
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

// TestStabilityDemotion: semantic instability after retries forbids
// DISMISSED/LOWERED — the permitted reduction collapses to UNCHANGED,
// support drops and the reason lands in demotions, limitations and a
// residual assumption. No attempt is selected as the better answer.

// TestStabilityUnstableWithoutReduction: instability under an already
// UNCHANGED candidate is still recorded — support drops even though no
// recommendation was lost.

// TestStabilityStableRecordsResult: a clean retry record stamps
// stability_result "stable" and never touches the composed outcome.

// TestDriftComposeError: a drifted input is a technical error, never a
// package — on_drift: error means composition fails closed instead of
// minting a new recommendation.

// TestStabilityAttemptProjection: the projection binds every canonical
// field of a real composed package — semantics on the left, provenance
// pins in the audit block.

func stabilityProofReport(status FalsifierVerificationStatus) FalsifierReport {
	r := FalsifierReport{
		SchemaVersion: FalsifierVerificationSchemaVersion,
		RuleSetHash:   strings.Repeat("07", 32),
		Proofs: []FalsifierProof{{
			ID: "fp-stability", ProposalID: "fp-stability", ClaimID: "c1", ConditionID: "cond-1",
			Kind: FalsifierCodeAbsent, Status: status, Basis: BasisCheckerVerified, Mandatory: true,
			RuleID: "rule-absence", RuleVersion: "v1", EvidenceRefs: []string{"ev-1"},
			Coverage: FalsifierCoverage{Scope: "snapshot", Completeness: "COMPLETE", SnapshotHash: strings.Repeat("cd", 32), BuildContextHash: "build-1", ClosureHash: "closure-hash-1", ClosureComplete: true, CoverageRuleVersion: "4", ScopeRule: evidencetools.CodeAbsenceScopeRule, ScopeComplete: true, ScopeHash: "scope-hash-1", ShippingRoots: []string{"cmd/app"}, PackageStates: map[string]string{"cmd/app": "LIVE"}, DynamicRelevanceRule: evidencetools.CodeAbsenceDynamicRule, DynamicRelevanceComplete: true,
				ExpectedSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}, CheckedSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}, AbsentSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}},
			Reason:  "deterministic checker result",
			History: []FalsifierTransition{{From: FalsifierUnknown, To: status, Reason: "deterministic checker result", RuleID: "rule-absence", RuleVersion: "v1"}},
		}},
	}
	bindCurrentCoverageInventory(&r.Proofs[0].Coverage)
	if status != FalsifierVerified {
		r.Proofs[0].Basis = BasisUnsupported
	}
	r.Hash = reportHash(r)
	return r
}

func TestStabilityFalsifierHashDifference(t *testing.T) {
	attempts := attemptSeries(2)
	attempts[0].FalsifierHash, attempts[1].FalsifierHash = "hash-a", "hash-b"
	if report := CheckStability(attempts); report.Stable || report.Drift {
		t.Fatalf("hash difference not semantic instability: %+v", report)
	}
	attempts[1].FalsifierHash = attempts[0].FalsifierHash
	if report := CheckStability(attempts); !report.Stable || report.Drift {
		t.Fatalf("equal proof hashes unstable: %+v", report)
	}
}

// TestStabilityReplayDrift: replay verifies the recorded retry report
// against the run's pinned provenance — a tampered stability.json is a
// technical error, and a consistent one replays cleanly.
func TestStabilityReplayDrift(t *testing.T) {
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
	var raw RawAgentDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.runDir, "raw-agent.json")), &raw); err != nil {
		t.Fatal(err)
	}
	writeStability := func(t *testing.T, mutate func(*StabilityDocument)) {
		doc := StabilityDocument{
			SchemaVersion: StabilitySchemaVersion,
			RunID:         raw.RunID,
			FindingID:     "scanner-123",
			StabilityReport: StabilityReport{
				Retries: 0,
				Stable:  true,
				Attempts: []StabilityAttempt{{
					Attempt:        1,
					Recommendation: RecommendationUnchanged,
					PromptHash:     f.promptHash,
					InputHash:      f.stored.Audit.FindingHash,
					SnapshotHash:   f.stored.Audit.SnapshotHash,
				}},
			},
		}
		mutate(&doc)
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.runDir, "stability.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("consistent record replays", func(t *testing.T) {
		writeStability(t, func(*StabilityDocument) {})
		rep, err := PrepareReplay(context.Background(), f.runDir)
		if err != nil {
			t.Fatalf("replay with consistent stability.json: %v", err)
		}
		if rep.Stability == nil || rep.Stability.Retries != 0 {
			t.Fatalf("stability record not loaded: %+v", rep.Stability)
		}
	})
	t.Run("attempt snapshot hash drifted", func(t *testing.T) {
		writeStability(t, func(d *StabilityDocument) {
			d.Attempts[0].SnapshotHash = strings.Repeat("ee", 32)
		})
		if _, err := PrepareReplay(context.Background(), f.runDir); err == nil ||
			!strings.Contains(err.Error(), "stability") {
			t.Fatalf("tampered attempt snapshot_hash replayed cleanly: %v", err)
		}
	})
	t.Run("attempt prompt hash drifted", func(t *testing.T) {
		writeStability(t, func(d *StabilityDocument) {
			d.Attempts[0].PromptHash = strings.Repeat("dd", 32)
		})
		if _, err := PrepareReplay(context.Background(), f.runDir); err == nil ||
			!strings.Contains(err.Error(), "stability") {
			t.Fatalf("tampered attempt prompt_hash replayed cleanly: %v", err)
		}
	})
	t.Run("bound to another run", func(t *testing.T) {
		writeStability(t, func(d *StabilityDocument) { d.RunID = "other-run" })
		if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
			t.Fatal("stability.json bound to another run replayed cleanly")
		}
	})
}

// TestStabilityDemotion: semantic instability after retries forbids
// DISMISSED/LOWERED — the permitted reduction collapses to UNCHANGED,
// support drops and the reason lands in demotions, limitations and a
// residual assumption. No attempt is selected as the better answer.
func TestStabilityDemotion(t *testing.T) {
	s0 := dismissedForStability()
	// Control: the same fixture without a stability report dismisses.
	ctrl, err := (Composer{}).Compose(context.Background(), s0, goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("control compose: %v", err)
	}
	if ctrl.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("control recommendation = %s, want DISMISSED", ctrl.MachineDisposition.Recommendation)
	}

	attempts := attemptSeries(2)
	attempts[1].Recommendation = RecommendationLowered
	report := CheckStability(attempts)

	pkg, err := (Composer{Stability: &report}).Compose(context.Background(), s0, goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("compose with stability report: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("unstable run kept %s; instability must forbid DISMISSED/LOWERED", pkg.MachineDisposition.Recommendation)
	}
	if pkg.TechnicalAssessment.StabilityResult != "unstable_demoted" {
		t.Fatalf("stability_result = %q, want unstable_demoted", pkg.TechnicalAssessment.StabilityResult)
	}
	demoted := false
	for _, d := range pkg.MachineDisposition.Demotions {
		if strings.Contains(d, "stability") {
			demoted = true
		}
	}
	if !demoted {
		t.Fatalf("demotions do not name stability: %v", pkg.MachineDisposition.Demotions)
	}
	recorded := false
	for _, l := range pkg.TechnicalAssessment.Limitations {
		if strings.Contains(l, "recommendation") {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("limitations do not carry the divergence reason: %v", pkg.TechnicalAssessment.Limitations)
	}
	assumption := false
	for _, a := range pkg.MachineDisposition.ResidualAssumptions {
		if a.ID == "assumption-agent-stability" && a.Status == ConditionUnknown {
			assumption = true
		}
	}
	if !assumption {
		t.Fatalf("residual_assumptions lack the stability assumption: %+v", pkg.MachineDisposition.ResidualAssumptions)
	}
	if err := pkg.Validate(); err != nil {
		t.Fatalf("demoted package fails validation: %v", err)
	}
}

// TestStabilityUnstableWithoutReduction: instability under an already
// UNCHANGED candidate is still recorded — support drops even though no
// recommendation was lost.
func TestStabilityUnstableWithoutReduction(t *testing.T) {
	s0 := goodStage0()
	// No package check resolves presence, so no rule may fire — the
	// candidate stays UNCHANGED and instability has no reduction to take.
	s0.PackageCheck = PackageCheckResult{
		Class:      CheckUnresolved,
		Provenance: []string{"module_graph"},
	}
	ctrl, err := (Composer{}).Compose(context.Background(), s0, goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("control compose: %v", err)
	}
	if ctrl.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("control fixture changed: %s", ctrl.MachineDisposition.Recommendation)
	}

	attempts := attemptSeries(2)
	attempts[1].SupportLevel = string(SupportLevelProvedWithinScope)
	report := CheckStability(attempts)

	pkg, err := (Composer{Stability: &report}).Compose(context.Background(), s0, goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("recommendation = %s", pkg.MachineDisposition.Recommendation)
	}
	if pkg.TechnicalAssessment.StabilityResult != "unstable" {
		t.Fatalf("stability_result = %q, want unstable", pkg.TechnicalAssessment.StabilityResult)
	}
	// Instability is a machine condition: the reduction is withheld and the
	// derived human support records the divergence on its own axis.
	if pkg.MachineDisposition.Automation != AutomationWarn {
		t.Fatalf("automation = %s, want WARN for a withheld reduction", pkg.MachineDisposition.Automation)
	}
	if !strings.Contains(strings.Join(pkg.Support.Reasons, "|"), "stability") {
		t.Fatalf("support does not record the unstable basis: %+v", pkg.Support)
	}
}

// TestStabilityStableRecordsResult: a clean retry record stamps
// stability_result "stable" and never touches the composed outcome.
func TestStabilityStableRecordsResult(t *testing.T) {
	report := CheckStability(attemptSeries(3))
	pkg, err := (Composer{Stability: &report}).Compose(
		context.Background(), dismissedForStability(), goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("stable report changed the recommendation: %s", pkg.MachineDisposition.Recommendation)
	}
	if pkg.TechnicalAssessment.StabilityResult != "stable" {
		t.Fatalf("stability_result = %q, want stable", pkg.TechnicalAssessment.StabilityResult)
	}
}

// TestDriftComposeError: a drifted input is a technical error, never a
// package — on_drift: error means composition fails closed instead of
// minting a new recommendation.
func TestDriftComposeError(t *testing.T) {
	report := StabilityReport{
		Retries:     1,
		Attempts:    attemptSeries(2),
		Stable:      true,
		Drift:       true,
		Limitations: []string{"attempt 2: provenance drift: snapshot_hash changed"},
	}
	_, err := (Composer{Stability: &report}).Compose(
		context.Background(), dismissedForStability(), goodAssessment(), completeValidation(), nil)
	if err == nil {
		t.Fatal("drifted stability report composed a package instead of failing")
	}
	if !strings.Contains(err.Error(), "drift") {
		t.Fatalf("error does not name drift: %v", err)
	}
}

// TestStabilityAttemptProjection: the projection binds every canonical
// field of a real composed package — semantics on the left, provenance
// pins in the audit block.
func TestStabilityAttemptProjection(t *testing.T) {
	pkg := composeOrFail(t, dismissedForStability(), goodAssessment(), completeValidation())
	at := ProjectStabilityAttempt(2, pkg)
	if at.Attempt != 2 {
		t.Fatalf("attempt = %d", at.Attempt)
	}
	if at.Recommendation != pkg.MachineDisposition.Recommendation ||
		at.ProfileID != pkg.MachineDisposition.RecommendedProfile.ID ||
		at.SupportLevel != string(pkg.Support.Level) ||
		at.Readiness != pkg.TechnicalAssessment.Status ||
		at.PolicyOutcome != string(pkg.MachineDisposition.Automation) {
		t.Fatalf("machine projection wrong: %+v", at)
	}
	// The human axis is projected from the package, not from the machine
	// disposition: judgment, action kind/scope and the computed support.
	if at.Judgment != string(pkg.Judgment.Verdict) ||
		at.ActionKind != string(pkg.ProposedAction.Kind) ||
		at.ActionScope != pkg.ProposedAction.Scope {
		t.Fatalf("human projection wrong: %+v", at)
	}
	if at.SnapshotHash != pkg.Audit.SnapshotHash || at.AdvisoryHash != pkg.Audit.AdvisoryHash ||
		at.ConfigHash != pkg.Audit.ConfigHash || at.RuleSetHash != pkg.Audit.RulesetHash ||
		at.SelectedRef != pkg.Audit.SelectedRef || at.ResolvedCommit != pkg.Audit.ResolvedCommit {
		t.Fatalf("provenance projection wrong: %+v", at)
	}
	for name, hash := range map[string]string{
		"judgment_hash": at.JudgmentHash, "action_hash": at.ActionHash,
		"premises_semantic_hash": at.PremisesSemanticHash, "premises_hash": at.PremisesHash,
		"support_semantic_hash": at.SupportSemanticHash, "support_hash": at.SupportHash,
		"machine_disposition_hash": at.MachineHash,
		"assumptions_hash":         at.AssumptionsHash,
		"triggers_hash":            at.TriggersHash,
		"toolchain_hash":           at.ToolchainHash,
		"input_hash":               at.InputHash,
	} {
		if hash == "" {
			t.Fatalf("projection left %s empty: %+v", name, at)
		}
	}
	// A second composition of the same inputs must produce an identical
	// projection — deterministic code never invents divergence.
	again := composeOrFail(t, dismissedForStability(), goodAssessment(), completeValidation())
	if report := CheckStability([]StabilityAttempt{at, ProjectStabilityAttempt(3, again)}); !report.Stable || report.Drift {
		t.Fatalf("identical compositions flagged: %+v", report)
	}
	// The projection is decisive-fact-bearing: at least one SUPPORTS or
	// REFUTES fact must land in the canonical list.
	if len(at.DecisiveFacts) == 0 {
		t.Fatal("projection recorded no decisive facts")
	}
}

func TestStabilityFalsifierVerifiedToUnknown(t *testing.T) {
	attempts := attemptSeries(2)
	attempts[0].Recommendation, attempts[0].SupportLevel, attempts[0].FalsifierHash = RecommendationDismissed, string(SupportLevelProvedWithinScope), "X"
	attempts[1].Recommendation, attempts[1].SupportLevel, attempts[1].FalsifierHash = RecommendationUnchanged, string(SupportLevelLimited), "Y"
	attempts[1].FalsifierHistory = []FalsifierTransition{{From: FalsifierVerified, To: FalsifierUnknown, Reason: "coverage widened"}}
	report := CheckStability(attempts)
	if report.Stable || report.Drift || len(report.Attempts) != 2 {
		t.Fatalf("verified to unknown stability = %+v", report)
	}
	pkg, err := (Composer{Stability: &report}).Compose(context.Background(), dismissedForStability(), goodAssessment(), completeValidation(), nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("unstable proof was not demoted: recommendation=%s", pkg.MachineDisposition.Recommendation)
	}
	if len(report.Attempts[1].FalsifierHistory) != 1 || report.Attempts[1].FalsifierHistory[0].From != FalsifierVerified {
		t.Fatalf("proof transition missing: %+v", report.Attempts[1].FalsifierHistory)
	}
}

func TestStabilityFalsifierSnapshotDrift(t *testing.T) {
	attempts := attemptSeries(2)
	attempts[1].SnapshotHash = "foreign-snapshot"
	report := CheckStability(attempts)
	if !report.Drift || !report.Stable {
		t.Fatalf("snapshot drift was not technical drift: %+v", report)
	}
	if _, err := (Composer{Stability: &report}).Compose(context.Background(), dismissedForStability(), goodAssessment(), completeValidation(), nil); err == nil {
		t.Fatal("snapshot drift composed a semantic package")
	}
}

func TestStabilityFalsifierRuleVersionDrift(t *testing.T) {
	attempts := attemptSeries(2)
	attempts[1].RuleSetHash = "foreign-ruleset"
	report := CheckStability(attempts)
	if !report.Drift || !report.Stable {
		t.Fatalf("ruleset drift was not technical drift: %+v", report)
	}
	if _, err := (Composer{Stability: &report}).Compose(context.Background(), dismissedForStability(), goodAssessment(), completeValidation(), nil); err == nil {
		t.Fatal("ruleset drift composed a semantic package")
	}
}

func TestStabilityPreservesProofHistory(t *testing.T) {
	report := stabilityProofReport(FalsifierVerified)
	a := assessmentWithProposal(goodAssessment(), declaredProofProposal("fp-stability", "c1", "cond-1"))
	pkg, err := (Composer{}).ComposeWithEvidence(context.Background(), dismissedForStability(), a, completeValidation(), EvidenceInput{Falsifiers: &report})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	attempt := ProjectStabilityAttempt(1, pkg)
	if len(attempt.FalsifierHistory) == 0 {
		t.Fatal("stability projection omitted proof history")
	}
	decision, err := json.Marshal(pkg)
	if err != nil || !strings.Contains(string(decision), "history") {
		t.Fatalf("decision.json omitted proof history: %v", err)
	}
	md := string(RenderDecisionMarkdown(pkg))
	if !strings.Contains(md, "Transition:") {
		t.Fatal("decision.md omitted proof transition")
	}
	audit := FalsifierAuditEvent(report, "run-1", 1, time.Unix(1, 0).UTC())
	b, _ := json.Marshal(audit)
	if !strings.Contains(string(b), "falsifier_verification") || !strings.Contains(string(b), "history") {
		t.Fatalf("audit omitted proof history: %s", b)
	}
}

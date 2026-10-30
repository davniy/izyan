package research

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestDecisionArtifactHumanContractRender(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV3
	r.DecisionArtifact = validArtifact(t)
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	for _, want := range []string{
		"Decision artifact — first screen",
		"Proposed action",
		"Mandatory facts (first screen; maximum 7)",
		"Environment questions (maximum 2)",
		"Branch matrix",
		"Structured justification",
		"Contradiction and unknown state",
		"Accept",
		"Reject",
		"ACCEPT_ENVIRONMENTAL_MITIGATION (contextual; not CLOSE_*)",
		"environment premise",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("render missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "environment assertion: `peer_trust`=`trusted`") {
		t.Fatal("renderer used legacy environment wording instead of explicit premise wording")
	}
}

func TestDecisionArtifactSidecarValidationRoundTrip(t *testing.T) {
	raw, err := json.Marshal(validArtifact(t))
	if err != nil {
		t.Fatal(err)
	}
	var got DecisionArtifact
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDecisionArtifact(&got); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(&got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("artifact JSON changed after round-trip")
	}
}

// artifactFirstScreen extracts the decision-artifact first-screen block
// of a rendered /3 report.
func artifactFirstScreen(t *testing.T, r *Report) string {
	t.Helper()
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	start := strings.Index(s, "## Decision artifact — first screen")
	if start < 0 {
		t.Fatalf("no first screen rendered:\n%s", s)
	}
	rest := s[start:]
	if end := strings.Index(rest, "\n## CVE essence"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// TestDecisionArtifactRendersEstablishedFacts proves the first screen
// shows the established VERIFIED facts the conservative action rests on
// even when the human contract names no mandatory refs — the 17/18
// acceptor finding. Degraded facts never render, cited facts lead
// uncited ones, and the MaxMandatoryFacts bound holds.
func TestDecisionArtifactRendersEstablishedFacts(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV3
	a := mutArtifact(t, func(a *DecisionArtifact) {
		a.HumanAction.MandatoryFactRefs = nil
		a.SharedFacts = append(a.SharedFacts,
			Fact{
				ID: "F-2", Proposition: "partial probe result that never verified",
				Subject: "golang.org/x/net", Scope: "go list -deps",
				SourceTool: "package-usage", ToolVersion: "v1",
				ObservationRefs: []string{"obs:OBS-0003"},
				DataDigest:      testDigest,
				Coverage:        FactCoveragePartial, Freshness: "this run",
				Status: FactStatusDegraded,
			},
			Fact{
				ID: "F-3", Proposition: "resolved version recorded for the module",
				Subject: "golang.org/x/net", Scope: "go module graph",
				SourceTool: "affected-resolve", ToolVersion: "v1",
				ObservationRefs: []string{"obs:OBS-0004"},
				DataDigest:      testDigest,
				Coverage:        FactCoverageComplete, Freshness: "this run",
				Status: FactStatusVerified,
			})
	})
	r.DecisionArtifact = a

	screen := artifactFirstScreen(t, r)
	if !strings.Contains(screen, "**`F-1`** [VERIFIED; coverage=COMPLETE]") {
		t.Fatalf("verified fact card missing:\n%s", screen)
	}
	if strings.Contains(screen, "F-2") {
		t.Fatalf("degraded fact reached the first screen:\n%s", screen)
	}
	if strings.Contains(screen, "none recorded; the proposed action is conservative") {
		t.Fatalf("first screen claims no facts while verified facts exist:\n%s", screen)
	}
	// Cited facts rank ahead of uncited verified facts.
	if strings.Index(screen, "F-1") > strings.Index(screen, "F-3") {
		t.Fatalf("branch-cited fact did not lead the fact list:\n%s", screen)
	}

	// The bound still holds when more verified facts exist.
	a2 := mutArtifact(t, func(a *DecisionArtifact) {
		a.HumanAction.MandatoryFactRefs = nil
		for i := range MaxMandatoryFacts + 3 {
			a.SharedFacts = append(a.SharedFacts, Fact{
				ID: fmt.Sprintf("F-X%d", i), Proposition: "extra verified fact",
				Subject: "golang.org/x/net", Scope: "go module graph",
				SourceTool: "affected-resolve", ToolVersion: "v1",
				ObservationRefs: []string{"obs:OBS-0005"},
				DataDigest:      testDigest,
				Coverage:        FactCoverageComplete, Freshness: "this run",
				Status: FactStatusVerified,
			})
		}
	})
	r.DecisionArtifact = a2
	screen = artifactFirstScreen(t, r)
	section := screen[strings.Index(screen, "### Mandatory facts"):]
	if j := strings.Index(section, "\n### "); j >= 0 {
		section = section[:j]
	}
	if n := strings.Count(section, "- **`"); n > MaxMandatoryFacts {
		t.Fatalf("first screen shows %d fact cards > bound %d", n, MaxMandatoryFacts)
	}
}

// TestDecisionArtifactFirstScreenHidesPlumbing proves the human-facing
// screen never surfaces run termination names, planner-failure wording,
// or the NOT_DECISION_READY enum — they are translated to plain
// language or omitted.
func TestDecisionArtifactFirstScreenHidesPlumbing(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV3
	r.DecisionArtifact = mutArtifact(t, func(a *DecisionArtifact) {
		a.Branches[0].Status = BranchNotDecisionReady
		a.Branches[0].ProposedDisposition = DispositionHoldUnknown
		a.Branches[0].Limitations = []string{
			"run terminated PLANNER_FAILURE (planner failed: planner exploded at step 3) — no decision-ready state was reached",
		}
		a.Branches[2].Limitations = append(a.Branches[2].Limitations,
			"the mandatory premise set exceeds the seven-fact bound — the artifact is NOT_DECISION_READY")
	})

	screen := artifactFirstScreen(t, r)
	for _, bad := range []string{
		"PLANNER_FAILURE", "NOT_DECISION_READY", "run terminated",
		"planner exploded", "planner failed",
	} {
		if strings.Contains(screen, bad) {
			t.Fatalf("plumbing text %q leaked into the first screen:\n%s", bad, screen)
		}
	}
	if !strings.Contains(screen,
		"the run stopped before reaching a decision-ready state: the planning step failed or produced no usable plan") {
		t.Fatalf("termination not translated to plain language:\n%s", screen)
	}
	if !strings.Contains(screen, "not decision-ready") {
		t.Fatalf("branch status not translated:\n%s", screen)
	}
}

// TestDecisionArtifactQuestionInstructionOnlyWhenDeclared proves the
// "answer the declared environment questions" instruction is emitted
// only when environment questions actually exist.
func TestDecisionArtifactQuestionInstructionOnlyWhenDeclared(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV3
	a := mutArtifact(t, func(a *DecisionArtifact) {
		a.HumanAction.EnvironmentQuestionRefs = nil
		a.HumanAction.Mode = HumanActionAcceptReject
	})
	r.DecisionArtifact = a
	d := decisionForArtifact(a, nil)
	r.Decision = &d

	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	if strings.Contains(s, "answer the declared environment questions") {
		t.Fatalf("question instruction emitted with zero declared questions:\n%s", s)
	}
	if !strings.Contains(s, "no environment answers are required") {
		t.Fatalf("missing explicit no-questions follow-up:\n%s", s)
	}

	a2 := validArtifact(t) // declares one question (peer_trust)
	d2 := decisionForArtifact(a2, nil)
	if !strings.Contains(d2.TicketRationale, "answer the declared environment questions") {
		t.Fatalf("declared question not surfaced in rationale: %q", d2.TicketRationale)
	}
}

// TestDecisionArtifactBlockedCloseExplanation proves that when verified
// facts satisfy a registered closure rule but the run never reached a
// decision-ready state, the first screen states why the stronger
// conclusion is prohibited instead of leaving the reader to guess.
func TestDecisionArtifactBlockedCloseExplanation(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV3
	r.DecisionArtifact = mutArtifact(t, func(a *DecisionArtifact) {
		a.Branches[0].Status = BranchNotDecisionReady
		a.Branches[0].ProposedDisposition = DispositionHoldUnknown
		a.Branches[0].Limitations = []string{
			"run terminated PLANNER_FAILURE (planner failed: no planner is configured) — no decision-ready state was reached",
		}
		a.JustificationGraph[0].RuleID = "rule.subject-absent-from-product-closure"
		a.JustificationGraph[0].Disposition = DispositionHoldUnknown
	})

	screen := artifactFirstScreen(t, r)
	if !strings.Contains(screen, "**Why not `CLOSE_NO_EXPLOIT_PATH`:**") {
		t.Fatalf("blocked stronger conclusion not explained:\n%s", screen)
	}
	if !strings.Contains(screen, "rule.subject-absent-from-product-closure") ||
		!strings.Contains(screen, "did not reach a decision-ready state") {
		t.Fatalf("prohibition reason incomplete:\n%s", screen)
	}

	// A close proposal itself never claims a blocked close.
	r.DecisionArtifact = mutArtifact(t, func(a *DecisionArtifact) {
		a.ProposedDisposition = DispositionCloseNoExploitPath
	})
	screen = artifactFirstScreen(t, r)
	if strings.Contains(screen, "Why not `CLOSE_") {
		t.Fatalf("blocked-close line emitted for a close proposal:\n%s", screen)
	}
}

// TestDecisionArtifactMultiEntrySummary proves the first screen
// summarizes the per-entry advisory status when the artifact binds more
// than one advisory entry.
func TestDecisionArtifactMultiEntrySummary(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV3
	r.DecisionArtifact = mutArtifact(t, func(a *DecisionArtifact) {
		a.AdvisoryBinding.SubjectRefs = []string{"adv-01", "adv-02"}
	})
	r.AffectedImplementations = append(r.AffectedImplementations, AffectedImplementation{
		ID: "adv-02", Ecosystem: "Go", Module: "modules.test/vuln", Binding: BindExact,
	})
	pa := &r.ProductApplicability
	pa.SelectedModule = strPtr("modules.test/vuln")
	pa.SelectedModules = []string{"modules.test/vuln"}
	pa.CheckedModules = []string{"golang.org/x/net", "modules.test/vuln"}

	screen := artifactFirstScreen(t, r)
	if !strings.Contains(screen, "### Advisory entry status") {
		t.Fatalf("multi-entry summary missing:\n%s", screen)
	}
	if !strings.Contains(screen, "**`adv-01`** — **fixed**") ||
		!strings.Contains(screen, "**`adv-02`** — **affected** (`modules.test/vuln`)") {
		t.Fatalf("per-entry statuses wrong:\n%s", screen)
	}
	if !strings.Contains(screen, "per-entry statuses differ") {
		t.Fatalf("mixed statuses not summarized:\n%s", screen)
	}

	// Single-entry advisories never get the block.
	r2 := validReport(t)
	r2.Schema = ReportSchemaV3
	r2.DecisionArtifact = validArtifact(t)
	if strings.Contains(artifactFirstScreen(t, r2), "### Advisory entry status") {
		t.Fatal("entry summary rendered for a single-entry advisory")
	}
}

package triage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// composeFixture composes a real decision package over the clean Stage 0
// fixture — mutate stages demoted/limited variants.
func composeFixture(t *testing.T, mutate func(*Stage0Result, *Assessment, *FactValidation)) DecisionPackage {
	t.Helper()
	s0, a, fv := goodStage0(), goodAssessment(), completeValidation()
	if mutate != nil {
		mutate(&s0, &a, &fv)
	}
	return composeOrFail(t, s0, a, fv)
}

// demotedFixture forces a check-based demotion: the machine disposition
// stays UNCHANGED with a recorded demotion and the human axes keep their own
// recorded values — the state decision.md must render without hiding any of
// it.
func demotedFixture(t *testing.T) DecisionPackage {
	t.Helper()
	return composeFixture(t, func(s0 *Stage0Result, a *Assessment, fv *FactValidation) {
		// A decision-relevant intake field left UNVERIFIED forces a demotion.
		for i := range s0.Validation.Fields {
			if s0.Validation.Fields[i].Field == "severity" {
				s0.Validation.Fields[i].Status = IntakeUnverified
				s0.Validation.Fields[i].BlocksRiskReduction = true
			}
		}
	})
}

// actionCardFixture composes the human package the card must present: a
// measured decisive leaf, an explicit interpretation, an external
// assumption, a counterargument and an unknown. The judgment is
// INCONCLUSIVE on purpose — an honest investigation opinion, not an error —
// and the proposed action is a concrete CLOSE instruction.
func actionCardFixture(t *testing.T) DecisionPackage {
	t.Helper()
	s0 := goodStage0()
	fact := "module example.org/library is absent from the recorded build graph"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	assessment := supportAssessment(
		[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{
			measuredObservationClaim("c1", fact, "ev-1"),
			{
				ID: "c2", Statement: "the captured build therefore never exercises the vulnerable function",
				Basis: PremiseInterpreted, Subject: "example.org/library usage", Scope: "captured build",
				DecisionRelevant: true, DependsOn: []string{"c1"},
			},
			{
				ID: "c3", Statement: "the captured build is the deployed artifact",
				Basis: PremiseAssumed, Subject: "deployment artifact", Scope: "captured build",
				DecisionRelevant: true, Owner: "security-team",
			},
		},
		[]Counterargument{{
			ID: "ca-1", Statement: "the module may be loaded through a runtime plugin",
			Response: "the recorded build graph contains no such module", PremiseIDs: []string{"c1"},
		}},
		"c1", "c2", "c3",
	)
	assessment.Unknowns = []Unknown{{
		ID: "u1", Description: "the deployment configuration was not captured",
		Reason: "no deployment manifest exists in the snapshot",
	}}
	pkg, err := (Composer{RulesetHash: strings.Repeat("07", 32)}).ComposeWithEvidence(
		context.Background(), s0, assessment, supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		EvidenceInput{Observations: []RecordedObservation{observation}, SelectedAttempt: 1},
	)
	if err != nil {
		t.Fatalf("ComposeWithEvidence: %v", err)
	}
	if err := pkg.Validate(); err != nil {
		t.Fatalf("action card fixture package invalid: %v", err)
	}
	return pkg
}

// actionCardOrder is the presentation order of the human action card. It
// starts with the action a person is asked to take, states the recorded
// scope before the evidence, and ends with the collapsed audit detail:
// reading the main body never requires walking the provider facts or the
// machine predicates.
var actionCardOrder = []string{
	"## Proposed action (human)",
	"## Why this action",
	"## Decision scope",
	"## Decisive measured and proved facts",
	"## Interpretations (model reasoning, not measured facts)",
	"## Assumptions, unknowns and support",
	"## What changes this recommendation",
	"## Accept or reject this proposal (human decision)",
	"## Machine disposition (deterministic)",
	"## Audit detail",
}

// actionCardForbidden enumerates phrasings that would present the human
// proposal as a machine-safe conclusion. Human instructions, explicit
// unknowns and an INCONCLUSIVE judgment are legitimate; authority claims
// about them are not.
var actionCardForbidden = []*regexp.Regexp{
	regexp.MustCompile(`\bNOT_AFFECTED\b`),
	regexp.MustCompile(`\bNO_EXPLOIT_PATH_FOUND\b`),
	regexp.MustCompile(`(?i)\bmachine[- ]safe\b`),
	regexp.MustCompile(`(?i)\bauto(matically)?[- ]?(close|dismiss|lower)\w*`),
	regexp.MustCompile(`(?i)\bapprove\b`),
}

// assertActionCardContract checks the human card's presentation contract
// for one package: the action-first order, the separately labelled axes,
// every recorded limitation, unknown and demotion, and the guarantee that
// the human proposal is never presented as a machine-safe verdict.
func assertActionCardContract(t *testing.T, pkg DecisionPackage, md string) {
	t.Helper()
	m := pkg.MachineDisposition
	if !strings.HasPrefix(md, "# Triage action package: ") {
		t.Fatalf("decision.md does not start with the finding identity:\n%s", md)
	}
	// The nine presentation sections appear in order.
	previous := -1
	for _, section := range actionCardOrder {
		idx := strings.Index(md, section)
		if idx < 0 {
			t.Fatalf("decision.md lacks section %q:\n%s", section, md)
		}
		if idx <= previous {
			t.Fatalf("decision.md section %q is out of order:\n%s", section, md)
		}
		previous = idx
	}
	// The proposed action and its concrete instruction lead the card.
	actionStart := strings.Index(md, actionCardOrder[0])
	actionEnd := strings.Index(md, actionCardOrder[1])
	actionSection := md[actionStart:actionEnd]
	for _, want := range []string{string(pkg.ProposedAction.Kind), pkg.ProposedAction.Instruction} {
		if want != "" && !strings.Contains(actionSection, want) {
			t.Fatalf("proposed action section lacks %q:\n%s", want, actionSection)
		}
	}
	if strings.Contains(actionSection, "Machine recommendation") {
		t.Fatalf("proposed action section carries a machine recommendation:\n%s", actionSection)
	}
	// The model judgment is labelled as opinion and rendered verbatim.
	if !strings.Contains(md, string(pkg.Judgment.Verdict)) {
		t.Fatalf("decision.md lacks the model judgment %q:\n%s", pkg.Judgment.Verdict, md)
	}
	if pkg.Judgment.Summary != "" && !strings.Contains(md, pkg.Judgment.Summary) {
		t.Fatalf("decision.md lacks the judgment summary:\n%s", md)
	}
	// The derived support is visible with its reasons.
	if !strings.Contains(md, string(pkg.Support.Level)) {
		t.Fatalf("decision.md lacks support level %q:\n%s", pkg.Support.Level, md)
	}
	for _, reason := range pkg.Support.Reasons {
		if !strings.Contains(md, reason) {
			t.Fatalf("decision.md lacks support reason %q:\n%s", reason, md)
		}
	}
	// The recorded scope is stated in the main body: the boundary, every
	// captured record with its digest, and the open boundaries. A model's
	// record_ids never widen it.
	scopeStart := strings.Index(md, "## Decision scope")
	scopeEnd := strings.Index(md, "## Decisive measured and proved facts")
	if scopeStart < 0 || scopeEnd <= scopeStart {
		t.Fatalf("decision.md lacks the decision scope section:\n%s", md)
	}
	scopeSection := md[scopeStart:scopeEnd]
	if !strings.Contains(scopeSection, string(pkg.Scope.Boundary)) {
		t.Fatalf("decision scope does not name boundary %q:\n%s", pkg.Scope.Boundary, scopeSection)
	}
	if pkg.Scope.SnapshotHash != "" && !strings.Contains(scopeSection, pkg.Scope.SnapshotHash) {
		t.Fatalf("decision scope hides the pinned snapshot %q:\n%s", pkg.Scope.SnapshotHash, scopeSection)
	}
	for _, rec := range pkg.Scope.Records {
		if !strings.Contains(scopeSection, rec.ID) || !strings.Contains(scopeSection, rec.SHA256) {
			t.Fatalf("decision scope lacks recorded record %+v:\n%s", rec, scopeSection)
		}
	}
	for _, boundary := range pkg.Scope.OpenBoundaries {
		if !strings.Contains(scopeSection, boundary) {
			t.Fatalf("decision scope hides open boundary %q:\n%s", boundary, scopeSection)
		}
	}
	if pkg.Scope.Boundary == DecisionBoundaryExactRecords {
		if !strings.Contains(scopeSection, "no CVE-wide statement") {
			t.Fatalf("record-bound decision scope does not state its CVE-wide limit:\n%s", scopeSection)
		}
	} else if !strings.Contains(scopeSection, "no advisory record with a recorded digest") {
		t.Fatalf("input-material-only scope does not state the missing record:\n%s", scopeSection)
	}
	// The machine disposition is separately labelled and appear once.
	if n := strings.Count(md, "**Machine recommendation:**"); n != 1 {
		t.Fatalf("decision.md shows %d machine recommendation lines:\n%s", n, md)
	}
	if !strings.Contains(md, string(m.Recommendation)) {
		t.Fatalf("decision.md lacks machine recommendation %q:\n%s", m.Recommendation, md)
	}
	if !strings.Contains(md, m.RecommendedProfile.ID) {
		t.Fatalf("decision.md lacks profile %q:\n%s", m.RecommendedProfile.ID, md)
	}
	if m.Rationale.Summary != "" && !strings.Contains(md, m.Rationale.Summary) {
		t.Fatalf("decision.md lacks the machine rationale summary:\n%s", md)
	}
	// Nothing recorded is hidden: unknowns, limitations and demotions.
	for _, u := range pkg.Unknowns {
		if u.Description != "" && !strings.Contains(md, u.Description) {
			t.Fatalf("decision.md hides unknown %q:\n%s", u.Description, md)
		}
	}
	for _, lim := range pkg.TechnicalAssessment.Limitations {
		if !strings.Contains(md, lim) {
			t.Fatalf("decision.md hides limitation %q:\n%s", lim, md)
		}
	}
	for _, d := range m.Demotions {
		if !strings.Contains(md, d) {
			t.Fatalf("decision.md hides demotion %q:\n%s", d, md)
		}
	}
	// No human proposal is sold as a machine-safe conclusion.
	for _, re := range actionCardForbidden {
		if hit := re.FindString(md); hit != "" {
			t.Fatalf("decision.md presents a machine-safe claim %q (pattern %s):\n%s", hit, re, md)
		}
	}
	// Provider facts and machine predicates stay inside the collapsed
	// audit detail.
	auditStart := strings.Index(md, actionCardOrder[len(actionCardOrder)-1])
	if auditStart < 0 || !strings.Contains(md, "<details>") || !strings.HasSuffix(strings.TrimSpace(md), "</details>") {
		t.Fatalf("decision.md lacks an expandable audit detail block:\n%s", md)
	}
	for _, f := range pkg.Facts {
		idx := strings.Index(md, "`"+f.ID+"`")
		if idx < 0 {
			t.Fatalf("decision.md hides fact %s:\n%s", f.ID, md)
		}
		if idx < auditStart {
			t.Fatalf("decision.md requires reading fact %s in the main body:\n%s", f.ID, md)
		}
	}
	machineStart := strings.Index(md, actionCardOrder[len(actionCardOrder)-2])
	machineSection := md[machineStart:auditStart]
	if strings.Contains(machineSection, "**Proposed action:**") {
		t.Fatalf("machine disposition section presents the human action as a machine result:\n%s", machineSection)
	}
	var predicates []Predicate
	for _, c := range m.ResidualAssumptions {
		predicates = append(predicates, c.Predicate)
	}
	for _, tr := range m.ReassessmentTriggers {
		predicates = append(predicates, tr.When)
	}
	for _, cp := range m.ConditionalProfiles {
		predicates = append(predicates, cp.Applicability.Predicate)
	}
	for _, p := range predicates {
		want, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		idx := strings.Index(md, string(want))
		if idx < 0 {
			t.Fatalf("decision.md hides machine predicate %s:\n%s", want, md)
		}
		if idx < auditStart {
			t.Fatalf("decision.md requires reading machine predicate %s in the main body:\n%s", want, md)
		}
	}
}

func TestDecisionMarkdownContract(t *testing.T) {
	t.Run("clean package", func(t *testing.T) {
		pkg := composeFixture(t, nil)
		md := string(RenderDecisionMarkdown(pkg))
		assertActionCardContract(t, pkg, md)
	})
	t.Run("demoted package", func(t *testing.T) {
		pkg := demotedFixture(t)
		if len(pkg.MachineDisposition.Demotions) == 0 {
			t.Fatal("fixture lost its demotion record")
		}
		if len(pkg.TechnicalAssessment.Limitations) == 0 {
			t.Fatal("fixture lost its limitations")
		}
		md := string(RenderDecisionMarkdown(pkg))
		assertActionCardContract(t, pkg, md)
		// Limitations and demotions stay visible — nothing is hidden.
		for _, lim := range pkg.TechnicalAssessment.Limitations {
			if !strings.Contains(md, lim) {
				t.Fatalf("decision.md hides limitation %q:\n%s", lim, md)
			}
		}
		for _, d := range pkg.MachineDisposition.Demotions {
			if !strings.Contains(md, d) {
				t.Fatalf("decision.md hides demotion %q:\n%s", d, md)
			}
		}
	})
}

// TestDecisionMarkdownActionFirst pins the human reading order: the action
// and its instruction come first, then the causal rationale and the model
// judgment, the decisive measured/proved facts, the separately labelled
// interpretations, the assumptions/unknowns/support, what changes the
// action, the Accept/Reject instructions and only then the separately
// labelled machine disposition. The provider facts and machine predicates
// stay in the collapsed audit detail.
func TestDecisionMarkdownActionFirst(t *testing.T) {
	pkg := actionCardFixture(t)
	if pkg.Judgment.Verdict != VerdictInconclusive {
		t.Fatalf("fixture judgment = %s, want the legitimate INCONCLUSIVE opinion", pkg.Judgment.Verdict)
	}
	md := string(RenderDecisionMarkdown(pkg))
	assertActionCardContract(t, pkg, md)

	// 1. The proposed action and instruction lead the card.
	actionStart := strings.Index(md, "## Proposed action (human)")
	rationaleStart := strings.Index(md, "## Why this action")
	instruction := strings.Index(md, pkg.ProposedAction.Instruction)
	if actionStart < 0 || rationaleStart <= actionStart || instruction < actionStart || instruction > rationaleStart {
		t.Fatalf("the action and instruction do not lead the card:\n%s", md)
	}
	// 2. The causal rationale precedes the model judgment.
	judgmentStart := strings.Index(md, "### Model judgment (investigation opinion, not a machine verdict)")
	if judgmentStart < rationaleStart || strings.Index(md, pkg.ProposedAction.Rationale) > judgmentStart {
		t.Fatalf("the rationale and judgment are not in the human reading order:\n%s", md)
	}
	if !strings.Contains(md, "INCONCLUSIVE") {
		t.Fatalf("an INCONCLUSIVE judgment is legitimate and must be shown:\n%s", md)
	}
	// 3./4. Measured facts and interpretations are separate sections: each
	// premise appears under its own computed basis, never conflated.
	measuredStart := strings.Index(md, "## Decisive measured and proved facts")
	interpStart := strings.Index(md, "## Interpretations (model reasoning, not measured facts)")
	supportStart := strings.Index(md, "## Assumptions, unknowns and support")
	measuredSection := md[measuredStart:interpStart]
	interpSection := md[interpStart:supportStart]
	measuredStatement := premiseStatement(t, pkg, "c1")
	interpretedStatement := premiseStatement(t, pkg, "c2")
	assumedStatement := premiseStatement(t, pkg, "c3")
	if !strings.Contains(measuredSection, measuredStatement) || !strings.Contains(measuredSection, "MEASURED") {
		t.Fatalf("measured premise missing from its section:\n%s", measuredSection)
	}
	if strings.Contains(measuredSection, interpretedStatement) {
		t.Fatalf("an interpretation is presented as a measured fact:\n%s", measuredSection)
	}
	if !strings.Contains(interpSection, interpretedStatement) || !strings.Contains(interpSection, "INTERPRETED") {
		t.Fatalf("interpretation missing from its labelled section:\n%s", interpSection)
	}
	if strings.Contains(interpSection, measuredStatement) {
		t.Fatalf("a measured fact is presented as an interpretation:\n%s", interpSection)
	}
	// 5. Assumptions, explicit unknowns and computed support.
	supportSection := md[supportStart:strings.Index(md, "## What changes this recommendation")]
	for _, want := range []string{assumedStatement, "ASSUMED", "security-team", string(pkg.Support.Level), "deployment configuration was not captured"} {
		if !strings.Contains(supportSection, want) {
			t.Fatalf("assumptions/support section lacks %q:\n%s", want, supportSection)
		}
	}
	// 6. What changes the action.
	changesSection := md[strings.Index(md, "## What changes this recommendation"):strings.Index(md, "## Accept or reject this proposal (human decision)")]
	for _, want := range pkg.ProposedAction.ReconsiderWhen {
		if !strings.Contains(changesSection, want) {
			t.Fatalf("the change conditions omit %q:\n%s", want, changesSection)
		}
	}
	// 7. Accept and Reject instructions.
	decisionSection := md[strings.Index(md, "## Accept or reject this proposal (human decision)"):strings.Index(md, "## Machine disposition (deterministic)")]
	for _, want := range []string{"--record-decision", "--decision accept", "--decision reject", "records a person's decision"} {
		if !strings.Contains(decisionSection, want) {
			t.Fatalf("Accept/Reject instructions lack %q:\n%s", want, decisionSection)
		}
	}
	// 8. The machine disposition is separate and explicitly labelled.
	machineStart := strings.Index(md, "## Machine disposition (deterministic)")
	auditStart := strings.Index(md, "## Audit detail")
	machineSection := md[machineStart:auditStart]
	if !strings.Contains(machineSection, "**Machine recommendation:**") ||
		!strings.Contains(machineSection, string(pkg.MachineDisposition.Recommendation)) {
		t.Fatalf("machine disposition not separately presented:\n%s", machineSection)
	}
	if strings.Contains(machineSection, pkg.ProposedAction.Instruction) {
		t.Fatalf("the machine disposition repeats the human instruction as its own:\n%s", machineSection)
	}
	// 9. Expandable audit detail is last and carries the provider surface.
	auditSection := md[auditStart:]
	if !strings.Contains(auditSection, "<details>") || !strings.HasSuffix(strings.TrimSpace(auditSection), "</details>") {
		t.Fatalf("audit detail is not the collapsed final section:\n%s", auditSection)
	}
	if len(pkg.Facts) == 0 {
		t.Fatal("fixture carries no provider facts; the audit assertion would be vacuous")
	}
	for _, f := range pkg.Facts {
		if !strings.Contains(auditSection, "`"+f.ID+"`") {
			t.Fatalf("audit detail lacks provider fact %s:\n%s", f.ID, auditSection)
		}
	}
}

// premiseStatement resolves one premise's verbatim statement from a package.
func premiseStatement(t *testing.T, pkg DecisionPackage, claimID string) string {
	t.Helper()
	for _, pr := range pkg.Premises {
		if pr.ClaimID == claimID {
			return pr.Statement
		}
	}
	t.Fatalf("package carries no premise %q", claimID)
	return ""
}

// TestDecisionAuditSeparatesResultAxes: the decision audit event records the
// judgment, the human action, the support and the machine disposition under
// distinct keys — no consumer can read the model's proposal as a machine
// result.
func TestDecisionAuditSeparatesResultAxes(t *testing.T) {
	pkg := actionCardFixture(t)
	raw, err := json.Marshal(DecisionAuditEvent(pkg, pkg.RunID, artifactClock()()))
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Decision map[string]json.RawMessage `json:"decision"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	nested := func(axis, key string) string {
		t.Helper()
		body, ok := event.Decision[axis]
		if !ok {
			t.Fatalf("audit event lacks the %q axis: %s", axis, raw)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatalf("audit axis %q: %v", axis, err)
		}
		value, ok := fields[key]
		if !ok {
			t.Fatalf("audit axis %q lacks %q: %s", axis, key, body)
		}
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			t.Fatalf("audit %s.%s: %v", axis, key, err)
		}
		return s
	}
	if got := nested("judgment", "verdict"); got != string(pkg.Judgment.Verdict) {
		t.Fatalf("audit judgment.verdict = %q", got)
	}
	if got := nested("human_action", "kind"); got != string(pkg.ProposedAction.Kind) {
		t.Fatalf("audit human_action.kind = %q", got)
	}
	if got := nested("human_action", "instruction"); got != pkg.ProposedAction.Instruction {
		t.Fatalf("audit human_action.instruction = %q", got)
	}
	if got := nested("support", "level"); got != string(pkg.Support.Level) {
		t.Fatalf("audit support.level = %q", got)
	}
	if got := nested("machine_disposition", "recommendation"); got != string(pkg.MachineDisposition.Recommendation) {
		t.Fatalf("audit machine_disposition.recommendation = %q", got)
	}
	// The retired flat keys must not come back: a single `recommendation` or
	// `proposed_action` key is exactly the conflation this split removes.
	for _, retired := range []string{"recommendation", "proposed_action", "support_level"} {
		if _, ok := event.Decision[retired]; ok {
			t.Fatalf("audit event reintroduced the conflated key %q: %s", retired, raw)
		}
	}
}

// TestDecisionMarkdownRendersFacts: verified facts keep id, kind, status,
// subject, scope and provenance; triggers carry their machine status.
func TestDecisionMarkdownRendersFacts(t *testing.T) {
	pkg := composeFixture(t, nil)
	md := string(RenderDecisionMarkdown(pkg))
	for _, f := range pkg.Facts {
		for _, want := range []string{f.ID, f.Kind, f.Status, f.Subject, f.Scope} {
			if want != "" && !strings.Contains(md, want) {
				t.Fatalf("decision.md lacks fact %s field %q:\n%s", f.ID, want, md)
			}
		}
	}
	for _, tr := range pkg.MachineDisposition.ReassessmentTriggers {
		if !strings.Contains(md, tr.ID) || !strings.Contains(md, string(tr.State)) {
			t.Fatalf("decision.md lacks trigger %s:\n%s", tr.ID, md)
		}
	}
	want := []string{
		"Support level", "Execution mode",
		pkg.TechnicalAssessment.FactValidation,
	}
	if b := pkg.MachineDisposition.Baseline; b != nil {
		want = append(want, "Baseline severity", b.Severity, b.Priority)
	} else {
		want = append(want, "Baseline: none recorded")
	}
	for _, w := range want {
		if !strings.Contains(md, w) {
			t.Fatalf("decision.md lacks %q:\n%s", w, md)
		}
	}
}

// TestDecisionMarkdownDeterministic: the card is a pure function of the
// package — two renders are byte-identical so replays diff cleanly.
func TestDecisionMarkdownDeterministic(t *testing.T) {
	pkg := demotedFixture(t)
	a, b := RenderDecisionMarkdown(pkg), RenderDecisionMarkdown(pkg)
	if string(a) != string(b) {
		t.Fatal("decision.md is not deterministic")
	}
}

// TestDecisionMarkdownInvalidPackage: a package that violates the contract
// still renders its recorded fields verbatim — the renderer never invents
// values and never repairs the document.
func TestDecisionMarkdownInvalidPackage(t *testing.T) {
	pkg := DecisionPackage{
		SchemaVersion: "bogus",
		FindingID:     "finding-example-001",
		MachineDisposition: MachineDisposition{
			Recommendation: Recommendation("TAMPERED"),
		},
	}
	md := string(RenderDecisionMarkdown(pkg))
	if !strings.Contains(md, "TAMPERED") {
		t.Fatalf("renderer must echo recorded values, got:\n%s", md)
	}
}

// decisionRunFixture binds the writeFixture run to a Stage 0 result so a
// composed package passes WriteDecision's provenance binding: snapshot hash
// and prompt hash come from the recorded artifacts.
func decisionStage0(in FindingInput, manifest SnapshotManifest) Stage0Result {
	s0 := goodStage0()
	s0.Input = in
	s0.Snapshot = manifest
	s0.Source.Metadata = manifest.Materialization
	return s0
}

// writeDecisionRun records a successful run and composes+writes the
// decision package bound to it, returning the artifacts and the package.
func writeDecisionRun(t *testing.T, out string) (RunArtifacts, DecisionPackage, Assessment) {
	t.Helper()
	ctx := context.Background()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock(), Model: "test-model", ToolVersions: map[string]string{"tools": "v1"}}
	art, err := w.Write(ctx, out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.FactValidationDetail == nil {
		t.Fatal("stored assessment lost fact_validation_detail")
	}
	s0 := decisionStage0(in, manifest)
	pkg, err := Composer{
		RulesetHash: strings.Repeat("07", 32),
		Limits: BudgetConfig{
			MaxLLMSteps: 32, MaxToolCalls: 128, MaxSourceBytes: 1 << 20, TimeoutSeconds: 900,
		},
	}.Compose(ctx, s0, stored, *stored.FactValidationDetail, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := w.WriteDecision(ctx, out, pkg); err != nil {
		t.Fatalf("WriteDecision: %v", err)
	}
	return art, pkg, stored
}

func TestDecisionArtifactsWritten(t *testing.T) {
	out := t.TempDir()
	art, pkg, _ := writeDecisionRun(t, out)

	// The complete success-run artifact set plus the optional files this
	// run produced (stage0.json/intake.json are absent: writeFixture has
	// no Stage 0 history; decision.json carries the binding instead).
	for _, name := range []string{
		"assessment.json", "assessment.md", "decision.json", "decision.md",
		"snapshot.json", "raw-agent.json", "input.json", "fact-gate.json",
		filepath.Join("audit", "events.jsonl"),
	} {
		info, err := os.Stat(filepath.Join(art.RootDir, name))
		if err != nil || info.IsDir() {
			t.Fatalf("artifact %s missing: %v", name, err)
		}
	}
	if art.DecisionPath != filepath.Join(art.RootDir, "decision.json") ||
		art.DecisionMarkdownPath != filepath.Join(art.RootDir, "decision.md") {
		t.Fatalf("decision paths = %q / %q", art.DecisionPath, art.DecisionMarkdownPath)
	}
	if art.FactGatePath != filepath.Join(art.RootDir, "fact-gate.json") {
		t.Fatalf("fact gate path = %q", art.FactGatePath)
	}

	// decision.json round-trips through the strict validator.
	data, err := os.ReadFile(art.DecisionPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateDecisionPackageJSON(data)
	if err != nil {
		t.Fatalf("decision.json rejected by the contract validator: %v", err)
	}
	if got.MachineDisposition.Recommendation != pkg.MachineDisposition.Recommendation || got.FindingID != pkg.FindingID {
		t.Fatalf("decision.json mismatch: %+v", got)
	}
	if got.Judgment != pkg.Judgment || got.ProposedAction.Kind != pkg.ProposedAction.Kind {
		t.Fatalf("decision.json lost the human axes: %+v", got)
	}
	// The audit block binds the package to input, config, snapshot,
	// advisory, ref, toolchain, ruleset, prompt and limits.
	au := got.Audit
	if au.TicketHash == "" || au.ConfigHash == "" || au.SnapshotHash == "" ||
		au.AdvisoryHash == "" || au.RulesetHash == "" || au.PromptHash == "" {
		t.Fatalf("audit binding incomplete: %+v", au)
	}

	// decision.md is the action-card rendering of the same package.
	md := string(mustRead(t, art.DecisionMarkdownPath))
	assertActionCardContract(t, pkg, md)

	// assessment.json is untouched by the decision write — the composed
	// decision never overwrites the agent record.
	var check Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &check); err != nil {
		t.Fatal(err)
	}
	if check.Audit == nil || check.Audit.AssessmentHash == "" {
		t.Fatal("assessment.json lost its audit block after WriteDecision")
	}

	// The decision audit event was appended to the same log.
	audit := string(mustRead(t, art.AuditPath))
	if !strings.Contains(audit, `"type":"decision"`) ||
		!strings.Contains(audit, string(pkg.MachineDisposition.Recommendation)) {
		t.Fatalf("audit log lacks the decision event:\n%s", audit)
	}
}

// TestDecisionArtifactsErrors: a package can only land in a run whose
// assessment exists and whose provenance it matches — everything else is
// a technical error, and no partial decision file is left behind.
func TestDecisionArtifactsErrors(t *testing.T) {
	ctx := context.Background()
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}

	pkg, err := Composer{}.Compose(ctx, decisionStage0(in, manifest), assessment,
		FactValidation{Status: ValidationComplete, References: []ReferenceCheck{}}, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}

	t.Run("run without assessment", func(t *testing.T) {
		dir := filepath.Join(out, "no-assessment")
		if err := w.WriteDecision(ctx, dir, pkg); err == nil {
			t.Fatal("WriteDecision accepted a directory without assessment.json")
		}
		if _, err := os.Stat(filepath.Join(dir, "decision.json")); !os.IsNotExist(err) {
			t.Fatal("decision.json leaked into a failed run directory")
		}
	})

	art, err := w.Write(ctx, out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The composed pkg binds to this run's snapshot hash and the recorded
	// prompt hash — reload the stored assessment and compose over it.
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	pkg, err = Composer{}.Compose(ctx, decisionStage0(in, manifest), stored,
		*stored.FactValidationDetail, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}

	t.Run("foreign finding", func(t *testing.T) {
		foreign := pkg
		foreign.FindingID = "scanner-999"
		if err := w.WriteDecision(ctx, out, foreign); err == nil {
			t.Fatal("WriteDecision accepted a package for another finding")
		}
	})
	t.Run("snapshot hash mismatch", func(t *testing.T) {
		drifted := pkg
		drifted.Audit.SnapshotHash = strings.Repeat("ff", 32)
		if err := w.WriteDecision(ctx, out, drifted); err == nil {
			t.Fatal("WriteDecision accepted a package bound to another snapshot")
		}
	})
	t.Run("prompt hash mismatch", func(t *testing.T) {
		drifted := pkg
		drifted.Audit.PromptHash = strings.Repeat("ee", 32)
		if err := w.WriteDecision(ctx, out, drifted); err == nil {
			t.Fatal("WriteDecision accepted a package bound to another prompt")
		}
	})
	t.Run("invalid package", func(t *testing.T) {
		bad := pkg
		bad.MachineDisposition.Automation = ""
		if err := w.WriteDecision(ctx, out, bad); err == nil {
			t.Fatal("WriteDecision accepted a contract-violating package")
		}
	})
	for _, name := range []string{"decision.json", "decision.md"} {
		if _, err := os.Stat(filepath.Join(art.RootDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s leaked after rejected WriteDecision", name)
		}
	}
}

// TestDecisionArtifactsAtomic: a failure mid-write leaves neither a
// partial decision.json/decision.md nor temp files — the pair lands or it
// does not.
func TestDecisionArtifactsAtomic(t *testing.T) {
	ctx := context.Background()
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}
	art, err := w.Write(ctx, out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	pkg, err := Composer{}.Compose(ctx, decisionStage0(in, manifest), stored,
		*stored.FactValidationDetail, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	// A directory occupying decision.md's final name breaks the rename.
	if err := os.MkdirAll(filepath.Join(art.RootDir, "decision.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecision(ctx, out, pkg); err == nil {
		t.Fatal("expected WriteDecision to fail")
	}
	if _, err := os.Stat(filepath.Join(art.RootDir, "decision.json")); !os.IsNotExist(err) {
		t.Fatal("decision.json survived a failed decision write")
	}
	entries, err := os.ReadDir(art.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	// Recovery: removing the blocker lets the same package land.
	if err := os.Remove(filepath.Join(art.RootDir, "decision.md")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecision(ctx, out, pkg); err != nil {
		t.Fatalf("recovery WriteDecision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(art.RootDir, "decision.md")); err != nil {
		t.Fatal("decision.md missing after recovery")
	}
}

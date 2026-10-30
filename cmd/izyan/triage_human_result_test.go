package main

// Phase 1 human-result workflow: run triage, read the action-first card,
// record Accept then Reject, replay offline from the saved artifacts alone,
// and compare the result with a deliberately disagreeing external control
// in the separate offline evaluator.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	triage "github.com/davniy/izyan/internal/productb/triage"
)

// copyTestTree duplicates a source fixture so the workflow can delete its
// working repository before replay and prove the saved run is self-contained.
func copyTestTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture tree: %v", err)
	}
	return dst
}

func sha256TestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// clearTriageLLMEnv removes every model setting: record and replay modes
// must work with no credentials and no endpoint.
func clearTriageLLMEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"LLM_ENABLED", "LLM_BASE_URL", "LLM_API_KEY",
		"LLM_ANALYZE_MODEL", "LLM_BUILD_MODEL",
		"LLM_TIMEOUT_SEC", "LLM_MAX_TOKENS", "LLM_INSECURE_TLS",
		"LLM_BUILD_MAX_RETRIES",
	} {
		t.Setenv(key, "")
	}
}

func findReplayDir(t *testing.T, out string) string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(out, "*-replay-*"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("replay output dir = %v, err=%v", entries, err)
	}
	return entries[0]
}

// TestTriageHumanResultAcceptRejectReplay is the complete Phase 1 workflow.
func TestTriageHumanResultAcceptRejectReplay(t *testing.T) {
	srv, models := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := copyTestTree(t, cliFixtureRepo(t))
	input := writeFindings(t, triageFinding("human-workflow-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runTriage([]string{"--input", input, "--out", out, "--vex-projection"})
	})
	if runErr != nil {
		t.Fatalf("live triage: %v", runErr)
	}
	line := strings.TrimSpace(stdout)
	if line == "" || strings.Contains(line, "\n") {
		t.Fatalf("completed triage did not print one primary-result line: %q", stdout)
	}

	dir := runDir(t, out, "human-workflow-1")
	// The exact prompt surface is persisted before/with the run so replay
	// verifies recorded bytes instead of today's tool definitions.
	promptInput := assertFile(t, filepath.Join(dir, triage.PromptInputArtifactName))
	if !strings.Contains(string(promptInput), "prompt-input.v1") || !strings.Contains(string(promptInput), "read_material") {
		t.Fatalf("prompt-input.v1 does not carry the advertised surface: %s", promptInput)
	}
	sourceDecision := assertFile(t, filepath.Join(dir, "decision.json"))
	pkg, err := triage.ValidateDecisionPackageJSON(sourceDecision)
	if err != nil {
		t.Fatalf("live decision package: %v", err)
	}

	// 2. The action-first card and the structured premise/support fields.
	if pkg.Judgment.Verdict != triage.VerdictNotExploitable ||
		pkg.ProposedAction.Kind != triage.HumanActionClose ||
		pkg.ProposedAction.Instruction == "" || pkg.ProposedAction.Rationale == "" {
		t.Fatalf("human axes missing: judgment=%+v action=%+v", pkg.Judgment, pkg.ProposedAction)
	}
	if len(pkg.Premises) == 0 || pkg.Support.Level == "" {
		t.Fatalf("structured premises/support missing: premises=%+v support=%+v", pkg.Premises, pkg.Support)
	}
	premiseIDs := map[string]bool{}
	for _, premise := range pkg.Premises {
		premiseIDs[premise.ClaimID] = true
	}
	for _, id := range pkg.ProposedAction.DecisiveClaimIDs {
		if !premiseIDs[id] {
			t.Fatalf("action cites decisive claim %q that the package does not carry", id)
		}
	}
	for _, id := range pkg.Support.DecisiveClaimIDs {
		if !premiseIDs[id] {
			t.Fatalf("support cites claim %q outside the premise set", id)
		}
	}
	// The compatibility finding transport binds the decision to the exact
	// captured finding record and its pinned snapshot; the action is
	// record-scoped rather than CVE-wide.
	if pkg.Scope.Boundary != triage.DecisionBoundaryExactRecords || len(pkg.Scope.Records) != 1 ||
		pkg.Scope.Records[0].ID != "CVE-2099-0001" || pkg.Scope.Records[0].SHA256 == "" {
		t.Fatalf("scope = %+v, want the captured record", pkg.Scope)
	}
	card := string(assertFile(t, filepath.Join(dir, "decision.md")))
	cardOrder := []string{
		"## Proposed action (human)",
		"## Why this action",
		"## Decision scope",
		"## Decisive measured and proved facts",
		"## Interpretations (model reasoning, not measured facts)",
		"## Assumptions, unknowns and support",
		"## What changes this recommendation",
		"## Accept or reject this proposal (human decision)",
		"## Machine disposition (deterministic)",
	}
	previous := -1
	for _, section := range cardOrder {
		idx := strings.Index(card, section)
		if idx < 0 || idx <= previous {
			t.Fatalf("card section %q missing or out of order:\n%s", section, card)
		}
		previous = idx
	}
	for _, want := range []string{
		pkg.ProposedAction.Instruction,
		pkg.ProposedAction.Rationale,
		string(pkg.Support.Level),
		string(pkg.Scope.Boundary),
		pkg.Scope.Records[0].ID,
		pkg.Scope.Records[0].SHA256,
		"no CVE-wide statement",
		pkg.Scope.SnapshotHash,
		"--record-decision",
		"--decision accept",
		"--decision reject",
	} {
		if !strings.Contains(card, want) {
			t.Fatalf("card lacks %q:\n%s", want, card)
		}
	}
	if pkg.MachineDisposition.Recommendation != triage.RecommendationUnchanged ||
		pkg.MachineDisposition.Automation != triage.AutomationWarn {
		t.Fatalf("machine disposition = %+v, want UNCHANGED/WARN", pkg.MachineDisposition)
	}
	if len(pkg.FalsifierProofs) != 0 {
		t.Fatalf("compatibility run produced proofs: %+v", pkg.FalsifierProofs)
	}

	// 3. Record Accept, then Reject, as two append-only history entries.
	clearTriageLLMEnv(t)
	callsBefore := len(*models)
	record := func(args ...string) string {
		var recordErr error
		text := captureStdout(t, func() { recordErr = runTriage(args) })
		if recordErr != nil {
			t.Fatalf("record decision: %v", recordErr)
		}
		return text
	}
	acceptLine := strings.TrimSpace(record("--record-decision", dir, "--decision", "accept", "--actor", "alice", "--reason", "reviewed the captured build graph"))
	rejectLine := strings.TrimSpace(record("--record-decision", dir, "--decision", "reject", "--actor", "bob", "--reason", "deployment evidence is still missing"))
	if !strings.Contains(acceptLine, "decision=ACCEPT") || !strings.Contains(rejectLine, "decision=REJECT") {
		t.Fatalf("record output = %q / %q", acceptLine, rejectLine)
	}
	if len(*models) != callsBefore {
		t.Fatalf("record mode called the model %d time(s)", len(*models)-callsBefore)
	}
	history, err := triage.ReadHumanDecisions(dir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions: %v", err)
	}
	if len(history) != 2 || history[0].Decision != triage.HumanDecisionAccept ||
		history[1].Decision != triage.HumanDecisionReject {
		t.Fatalf("review history = %+v", history)
	}
	sourceRecords := map[string][]byte{}
	for _, rec := range history {
		path := filepath.Join(dir, "human-decisions", rec.ID+".json")
		sourceRecords[rec.ID] = assertFile(t, path)
	}

	// 4./5. Replay with no model credentials and no original repository.
	if err := os.RemoveAll(repo); err != nil {
		t.Fatalf("remove working repository: %v", err)
	}
	replayOut := filepath.Join(t.TempDir(), "replay")
	if err := runTriage([]string{"--replay-run", dir, "--out", replayOut, "--vex-projection"}); err != nil {
		t.Fatalf("offline replay without model or repository: %v", err)
	}
	replayDir := findReplayDir(t, replayOut)
	var replay triage.ReplayDocument
	if err := json.Unmarshal(assertFile(t, filepath.Join(replayDir, "replay.json")), &replay); err != nil {
		t.Fatalf("replay.json: %v", err)
	}
	if replay.SchemaVersion != triage.ReplaySchemaVersion {
		t.Fatalf("replay schema = %q", replay.SchemaVersion)
	}
	if replay.DecisionHash == "" || replay.DecisionHash != replay.SourceDecisionHash || !replay.DecisionHashMatch {
		t.Fatalf("decision hash changed across replay: %+v", replay)
	}
	for _, match := range []bool{
		replay.JudgmentMatch, replay.ActionMatch, replay.PremisesMatch,
		replay.SupportMatch, replay.MachineDispositionMatch, replay.AssessmentHashMatch,
	} {
		if !match {
			t.Fatalf("a recorded result axis drifted across replay: %+v", replay)
		}
	}
	if got := assertFile(t, filepath.Join(replayDir, "decision.json")); string(got) != string(sourceDecision) {
		t.Fatal("replayed decision.json differs byte-wise from the source package")
	}
	if got := assertFile(t, filepath.Join(replayDir, triage.PromptInputArtifactName)); string(got) != string(promptInput) {
		t.Fatal("replay did not copy the recorded prompt-input.v1 surface verbatim")
	}
	replayedPkg, err := triage.ValidateDecisionPackageJSON(assertFile(t, filepath.Join(replayDir, "decision.json")))
	if err != nil {
		t.Fatalf("replayed package: %v", err)
	}
	if replayedPkg.Judgment != pkg.Judgment {
		t.Fatalf("replay rewrote the judgment: %+v != %+v", replayedPkg.Judgment, pkg.Judgment)
	}
	if replayedPkg.ProposedAction.Kind != pkg.ProposedAction.Kind ||
		replayedPkg.ProposedAction.Instruction != pkg.ProposedAction.Instruction {
		t.Fatalf("replay rewrote the proposed action: %+v != %+v", replayedPkg.ProposedAction, pkg.ProposedAction)
	}
	if len(replay.HumanDecisions) != 2 ||
		replay.HumanDecisions[0].Decision != triage.HumanDecisionAccept ||
		replay.HumanDecisions[1].Decision != triage.HumanDecisionReject {
		t.Fatalf("replay lost the review history: %+v", replay.HumanDecisions)
	}
	if len(replay.HumanDecisionHashes) != 2 {
		t.Fatalf("replay review hashes = %v", replay.HumanDecisionHashes)
	}
	for i, rec := range replay.HumanDecisions {
		want := sha256TestHex(sourceRecords[rec.ID])
		if replay.HumanDecisionHashes[i] != want {
			t.Fatalf("replay review hash[%d] = %q, want source hash %q", i, replay.HumanDecisionHashes[i], want)
		}
		copied := assertFile(t, filepath.Join(replayDir, "human-decisions", rec.ID+".json"))
		if string(copied) != string(sourceRecords[rec.ID]) {
			t.Fatalf("replay rewrote review record %s", rec.ID)
		}
	}
	if got := assertFile(t, filepath.Join(dir, "decision.json")); string(got) != string(sourceDecision) {
		t.Fatal("recording or replay modified the source decision package")
	}

	// 6. No new machine reduction and no VEX permission appeared.
	if replayedPkg.MachineDisposition.Recommendation != pkg.MachineDisposition.Recommendation ||
		replayedPkg.MachineDisposition.Automation != pkg.MachineDisposition.Automation {
		t.Fatalf("replay changed the machine disposition: %+v != %+v", replayedPkg.MachineDisposition, pkg.MachineDisposition)
	}
	assertNoFile(t, filepath.Join(dir, "vex.json"))
	assertNoFile(t, filepath.Join(replayDir, "vex.json"))
	audit := string(assertFile(t, filepath.Join(replayDir, "audit", "events.jsonl")))
	if !strings.Contains(audit, `"type":"vex_projection"`) || !strings.Contains(audit, `"status":"denied"`) {
		t.Fatalf("replay did not record the denied VEX projection: %s", audit)
	}
	if _, err := triage.ProjectVEX(replayedPkg); err == nil {
		t.Fatal("a package without a machine reduction produced a VEX permission")
	}

	// 7. Offline evaluation against a deliberately disagreeing control is
	// a separate error channel: live delivery stays intact and the machine
	// counters do not absorb the human comparison failures.
	baselinePath := filepath.Join(t.TempDir(), "baselines.json")
	baseline := `{"schema_version":"triage-baselines.v1","baselines":[
		{"finding_id":"human-workflow-1","disposition":"UNCHANGED","expected_judgment":"EXPLOITABLE","source":"disagreeing-external-control"}]}`
	if err := os.WriteFile(baselinePath, []byte(baseline), 0o644); err != nil {
		t.Fatal(err)
	}
	evalOut := filepath.Join(t.TempDir(), "eval")
	evalErr := runTriageEval([]string{"--run", dir, "--baseline", baselinePath, "--out", evalOut})
	wantExit(t, evalErr, triageEvalExitViolation)
	var evaluation triage.DecisionEvaluation
	if err := json.Unmarshal(assertFile(t, filepath.Join(evalOut, "evaluation.json")), &evaluation); err != nil {
		t.Fatalf("evaluation.json: %v", err)
	}
	if evaluation.FindingID != "human-workflow-1" ||
		evaluation.DecisionPackageHash != replay.DecisionHash ||
		evaluation.Coverage.ControlDisposition != triage.ComparisonAssessed ||
		evaluation.Coverage.ExpectedJudgment != triage.ComparisonAssessed {
		t.Fatalf("evaluation identity/coverage = %+v", evaluation)
	}
	if evaluation.Human.ReductionControlMismatches != 1 ||
		evaluation.Human.IncorrectNegativeJudgments != 1 ||
		evaluation.Human.CloseOnExploitable != 1 {
		t.Fatalf("human comparison counters = %+v", evaluation.Human)
	}
	if evaluation.Machine.Reductions != 0 || evaluation.Machine.FalseSafe != 0 ||
		evaluation.Machine.UnverifiedReductions != 0 {
		t.Fatalf("human mistakes leaked into machine counters: %+v", evaluation.Machine)
	}
	if len(evaluation.Violations) != 3 {
		t.Fatalf("evaluation violations = %v, want 3 measured human comparison failures", evaluation.Violations)
	}
	if got := assertFile(t, filepath.Join(dir, "decision.json")); string(got) != string(sourceDecision) {
		t.Fatal("offline evaluation modified the saved decision package")
	}
}

// TestTriageHumanResultDoesNotPublishMachineSafe pins the exit-code
// boundary: exit 0 means the human package was delivered, not that a
// machine reduction or VEX statement was established. The same package
// still trips an explicitly requested CI threshold, and no human or
// model-authored field can turn it into a machine-safe result.
func TestTriageHumanResultDoesNotPublishMachineSafe(t *testing.T) {
	// A static reply without the det tool call leaves the cited observation
	// unresolved: the package is deliverable, the machine basis is partial.
	srv, _ := fakeTriageLLM(t, staticReply(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("human-not-safe-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	var runErr error
	_ = captureStdout(t, func() {
		runErr = runTriage([]string{"--input", input, "--out", out, "--vex-projection"})
	})
	if runErr != nil {
		t.Fatalf("a delivered human package must exit 0: %v", runErr)
	}
	dir := runDir(t, out, "human-not-safe-1")
	pkg, err := triage.ValidateDecisionPackageJSON(assertFile(t, filepath.Join(dir, "decision.json")))
	if err != nil {
		t.Fatalf("decision package: %v", err)
	}
	if pkg.ProposedAction.Kind != triage.HumanActionClose || pkg.ProposedAction.Instruction == "" {
		t.Fatalf("human action was not delivered: %+v", pkg.ProposedAction)
	}
	if pkg.MachineDisposition.Recommendation != triage.RecommendationUnchanged ||
		pkg.MachineDisposition.Automation != triage.AutomationWarn {
		t.Fatalf("machine disposition = %+v, want UNCHANGED/WARN", pkg.MachineDisposition)
	}
	// Exit 0 is delivery, not permission: an explicit threshold still
	// reports the unchanged disposition as a CI failure.
	if !triage.PackagePolicyHit(pkg, triage.FailOnUnchanged) {
		t.Fatal("UNCHANGED package does not trip the unchanged threshold")
	}
	if code := triage.ExitCode(nil, []triage.DecisionPackage{pkg}, 0, []triage.FailOn{triage.FailOnUnchanged}); code != triage.ExitCodePolicy {
		t.Fatalf("explicit threshold exit = %d, want %d", code, triage.ExitCodePolicy)
	}
	if code := triage.ExitCode(nil, []triage.DecisionPackage{pkg}, 0, nil); code != triage.ExitCodeOK {
		t.Fatalf("delivery exit = %d, want %d", code, triage.ExitCodeOK)
	}

	// No human/model field can satisfy the VEX prerequisite or a machine
	// reduction, and the projection stays default-off/denied.
	assertNoFile(t, filepath.Join(dir, "vex.json"))
	if _, err := triage.ProjectVEX(pkg); err == nil {
		t.Fatal("an UNCHANGED package produced a VEX not_affected statement")
	}
	for _, path := range []string{filepath.Join(dir, "decision.json"), filepath.Join(dir, "decision.md")} {
		body := string(assertFile(t, path))
		for _, forbidden := range []string{"NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s presents a Product A authority verdict %q", path, forbidden)
			}
		}
	}
	audit := string(assertFile(t, filepath.Join(dir, "audit", "events.jsonl")))
	if !strings.Contains(audit, `"type":"vex_projection"`) || !strings.Contains(audit, `"status":"denied"`) {
		t.Fatalf("denied VEX projection was not recorded: %s", audit)
	}
}

// TestTriageHumanResultBudgetFinalization records a run whose initial
// exchange budget forced the bounded finalization turn. The package must
// carry that budget outcome, keep the delivered action, and replay it
// byte-identically — a finalized run is never presented as an investigation
// that ran to completion.
func TestTriageHumanResultBudgetFinalization(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("human-budget-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out, "--max-steps", "1"}); err != nil {
		t.Fatalf("budgeted triage: %v", err)
	}
	dir := runDir(t, out, "human-budget-1")
	pkg, err := triage.ValidateDecisionPackageJSON(assertFile(t, filepath.Join(dir, "decision.json")))
	if err != nil {
		t.Fatalf("decision package: %v", err)
	}
	if pkg.TechnicalAssessment.BudgetResult != "finalized_after_step_budget" {
		t.Fatalf("budget result = %q", pkg.TechnicalAssessment.BudgetResult)
	}
	if pkg.ProposedAction.Kind != triage.HumanActionClose || pkg.ProposedAction.Instruction == "" {
		t.Fatalf("finalization did not deliver an action: %+v", pkg.ProposedAction)
	}
	if pkg.MachineDisposition.Recommendation != triage.RecommendationUnchanged {
		t.Fatalf("budgeted run produced machine %s", pkg.MachineDisposition.Recommendation)
	}
	card := string(assertFile(t, filepath.Join(dir, "decision.md")))
	if !strings.Contains(card, "finalized_after_step_budget") {
		t.Fatalf("card hides the budget outcome:\n%s", card)
	}
	if strings.Contains(strings.ToLower(card), "investigation complete") {
		t.Fatalf("card claims the budgeted investigation was complete:\n%s", card)
	}

	clearTriageLLMEnv(t)
	replayOut := filepath.Join(t.TempDir(), "replay")
	if err := runTriage([]string{"--replay-run", dir, "--out", replayOut}); err != nil {
		t.Fatalf("replay budgeted run: %v", err)
	}
	replayDir := findReplayDir(t, replayOut)
	if got := assertFile(t, filepath.Join(replayDir, "decision.json")); string(got) != string(assertFile(t, filepath.Join(dir, "decision.json"))) {
		t.Fatal("replay changed the budgeted decision package")
	}
}

// TestTriageHumanResultCopiedCompatibilityRunReplays: the compatibility
// binding stores the captured finding record as the run-relative
// input.json. A completed run copied elsewhere replays from its own bytes
// after the original directory (and source repository) is gone.
func TestTriageHumanResultCopiedCompatibilityRunReplays(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := copyTestTree(t, cliFixtureRepo(t))
	input := writeFindings(t, triageFinding("human-copy-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("live triage: %v", err)
	}
	sourceDir := runDir(t, out, "human-copy-1")
	sourceDecision := assertFile(t, filepath.Join(sourceDir, "decision.json"))

	var stage0 struct {
		Advisory struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		} `json:"advisory"`
	}
	if err := json.Unmarshal(assertFile(t, filepath.Join(sourceDir, "stage0.json")), &stage0); err != nil {
		t.Fatalf("stage0.json: %v", err)
	}
	if stage0.Advisory.Path != "input.json" || stage0.Advisory.SHA256 == "" {
		t.Fatalf("captured record binding = %+v, want run-relative input.json with a digest", stage0.Advisory)
	}
	inputBytes := assertFile(t, filepath.Join(sourceDir, "input.json"))
	if stage0.Advisory.Size > 0 && int64(len(inputBytes)) != stage0.Advisory.Size {
		t.Fatalf("captured record size = %d, input.json = %d", stage0.Advisory.Size, len(inputBytes))
	}

	copiedDir := copyTestTree(t, sourceDir)
	clearTriageLLMEnv(t)
	if err := os.RemoveAll(out); err != nil {
		t.Fatalf("remove original run: %v", err)
	}
	if err := os.RemoveAll(repo); err != nil {
		t.Fatalf("remove source repository: %v", err)
	}
	replayOut := filepath.Join(t.TempDir(), "replay")
	if err := runTriage([]string{"--replay-run", copiedDir, "--out", replayOut}); err != nil {
		t.Fatalf("replay copied run: %v", err)
	}
	replayDir := findReplayDir(t, replayOut)
	if got := assertFile(t, filepath.Join(replayDir, "decision.json")); string(got) != string(sourceDecision) {
		t.Fatal("copied-run replay changed the decision package")
	}
}

// cliAssessmentCataloglessProposal carries a falsifier proposal even though
// the run supplies no condition catalog. The assessment is otherwise valid:
// the packet, evidence and claim are complete, so only catalog admission can
// refuse the proposal.
const cliAssessmentCataloglessProposal = `{
  "schema_version": "assessment.v3",
  "verdict": "NOT_EXPLOITABLE",
  "summary": "the declared vulnerable module is absent from the product snapshot",
  "claims": [
    {"id": "c1", "statement": "the product snapshot carries no vulnerable component", "basis": "INTERPRETED", "subject": "vulnerable component presence", "scope": "captured product snapshot", "decision_relevant": true, "evidence_refs": ["ev-1"]}
  ],
  "evidence": [
    {"id": "ev-1", "kind": "det", "locator": "det:det-0001"}
  ],
  "proposed_action": {"kind": "CLOSE", "instruction": "close the ticket as not exploitable", "rationale": "the recorded snapshot carries no vulnerable component", "scope": "captured product snapshot", "decisive_claim_ids": ["c1"], "reconsider_when": ["the vulnerable component appears in a captured snapshot"]},
  "falsifier_proposals": [
    {"id": "fp-1", "claim_id": "c1", "condition_id": "cond-CVE-2099-0001", "kind": "code_absent", "subjects": [{"package": "example.org/ghostpkg", "symbol": "GhostFn"}], "evidence_refs": ["ev-1"]}
  ]
}`

// TestNoCatalogRequiresNoProposalRepair: without a supplied condition
// catalog the prompt says machine falsifier proposals are unavailable, the
// run terminates after the agent's answer (no repair turn for a missing run
// binding), and the human action still ships with no machine reduction.
func TestNoCatalogRequiresNoProposalRepair(t *testing.T) {
	srv, models := fakeTriageLLM(t, detThenAssessment(cliAssessmentCataloglessProposal))
	repo := copyTestTree(t, cliFixtureRepo(t))
	input := writeFindings(t, triageFinding("no-catalog-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("no-catalog triage: %v", err)
	}
	if len(*models) != 2 {
		t.Fatalf("no-catalog run made %d model call(s), want 2 (no proposal repair turn)", len(*models))
	}

	dir := runDir(t, out, "no-catalog-1")
	promptInput := string(assertFile(t, filepath.Join(dir, triage.PromptInputArtifactName)))
	for _, want := range []string{
		"Machine falsifier proposals are unavailable in this run",
		"no condition catalog is bound to this run",
		"Proposals are optional",
	} {
		if !strings.Contains(promptInput, want) {
			t.Fatalf("no-catalog prompt missing %q", want)
		}
	}
	if strings.Contains(promptInput, `"condition_id":"cond-CVE-2099-0001"`) {
		t.Fatal("no-catalog prompt advertises the advisory-derived condition id")
	}

	pkg := readDecision(t, dir)
	if pkg.ProposedAction.Kind != triage.HumanActionClose || pkg.ProposedAction.Instruction == "" {
		t.Fatalf("human action lost without a catalog: %+v", pkg.ProposedAction)
	}
	if pkg.MachineDisposition.Recommendation != triage.RecommendationUnchanged ||
		pkg.MachineDisposition.Automation == triage.AutomationAllow {
		t.Fatalf("no-catalog run minted a machine reduction: %+v", pkg.MachineDisposition)
	}
	if len(pkg.FalsifierProofs) != 0 {
		t.Fatalf("no-catalog run published falsifier proofs: %+v", pkg.FalsifierProofs)
	}
}

// TestBranchReviewCLIOfflineSmoke executes the real CLI after closing the only
// scripted model endpoint and deleting the original checkout. Answer, decision
// and replay can therefore use only the captured contract and run artifacts.
func branchReviewCLIFixture(t *testing.T) (string, triage.DecisionPackage) {
	t.Helper()
	var assessment triage.Assessment
	if err := json.Unmarshal([]byte(cliAssessmentDet), &assessment); err != nil { t.Fatal(err) }
	assessment.ProposedAction.Kind = triage.HumanActionKeepOpen
	assessment.EnvironmentVariables = []triage.EnvironmentVariableProposal{{ID: triage.VariableDeploymentPerimeter}}
	for _, value := range []string{"cluster-internal", "public", triage.EnvironmentUnknown} {
		action := assessment.ProposedAction
		if value == "cluster-internal" { action.Kind = triage.HumanActionAcceptEnvironmentalMitigation }
		assessment.ConditionalActions = append(assessment.ConditionalActions, triage.ConditionalActionProposal{Assignments: map[string]string{triage.VariableDeploymentPerimeter: value}, Judgment: triage.LLMJudgment{Verdict: triage.VerdictInconclusive}, Action: action})
	}
	response, err := json.Marshal(assessment); if err != nil { t.Fatal(err) }
	srv, _ := fakeTriageLLM(t, detThenAssessment(string(response)))
	repo := copyTestTree(t, cliFixtureRepo(t))
	input := writeFindings(t, triageFinding("branch-review-cli", repo))
	out := filepath.Join(t.TempDir(), "live")
	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil { t.Fatal(err) }
	dir := runDir(t, out, "branch-review-cli")
	pkg := readDecision(t, dir)
	if len(pkg.HumanReviewPlan.Variables) != 1 { t.Fatalf("missing captured question: %+v", pkg.HumanReviewPlan) }
	srv.Close()
	if err := os.RemoveAll(repo); err != nil { t.Fatal(err) }
	clearTriageLLMEnv(t)
	return dir, pkg
}

func TestBranchReviewCLIOfflineSmoke(t *testing.T) {
	dir, pkg := branchReviewCLIFixture(t)
	binary := filepath.Join(t.TempDir(), "izyan")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil { t.Fatalf("build smoke binary: %s: %v", output, err) }
	run := func(args ...string) string {
		t.Helper(); command := exec.Command(binary, append([]string{"triage"}, args...)...)
		output, err := command.CombinedOutput(); if err != nil { t.Fatalf("CLI %v: %s: %v", args, output, err) }; t.Logf("CLI %v\n%s", args, output); return string(output)
	}
	selected := run("--record-decision", dir, "--actor", "operator", "--answer", "deployment_perimeter=cluster-internal")
	if !strings.Contains(selected, "action=ACCEPT_ENVIRONMENTAL_MITIGATION") || !strings.Contains(selected, "status=COMPLETE") { t.Fatal(selected) }
	pin := presentedReviewProjection(t, selected)
	run("--record-decision", dir, "--actor", "operator", "--decision", "accept", "--projection-hash", pin)
	run("--record-decision", dir, "--actor", "operator", "--decision", "reject", "--projection-hash", pin)
	replayOut := filepath.Join(t.TempDir(), "replay")
	run("--replay-run", dir, "--out", replayOut)
	replayDir := findReplayDir(t, replayOut)
	for _, collection := range []string{"environment-assertions", "human-decisions"} {
		entries, err := os.ReadDir(filepath.Join(dir, collection)); if err != nil { t.Fatal(err) }
		for _, e := range entries {
			before := assertFile(t, filepath.Join(dir, collection, e.Name()))
			after := assertFile(t, filepath.Join(replayDir, collection, e.Name()))
			if string(before) != string(after) { t.Fatal("replay rewrote original review bytes") }
		}
	}
	history, err := triage.ReadHumanDecisions(replayDir, pkg)
	if err != nil || len(history) != 2 { t.Fatalf("replayed history: %+v %v", history, err) }
	if string(assertFile(t, filepath.Join(dir, "decision.json"))) != string(assertFile(t, filepath.Join(replayDir, "decision.json"))) { t.Fatal("review changed machine/package claims") }
}

func presentedReviewProjection(t *testing.T, output string) string {
	t.Helper()
	for _, field := range strings.Fields(output) {
		if value, ok := strings.CutPrefix(field, "projection="); ok && len(value) == 64 { return value }
	}
	t.Fatalf("missing presented projection: %s", output)
	return ""
}

func TestBranchReviewCLIRejectsInterleavedSelection(t *testing.T) {
	dir, pkg := branchReviewCLIFixture(t)
	var reviewErr error
	first := captureStdout(t, func() { reviewErr = runTriage([]string{"--record-decision",dir,"--actor","alice","--answer","deployment_perimeter=public"}) })
	if reviewErr != nil || !strings.Contains(first,"action=KEEP_OPEN") { t.Fatalf("Alice presentation: %s %v",first,reviewErr) }
	oldPin := presentedReviewProjection(t,first)
	if !strings.Contains(first,"--decision accept --projection-hash "+oldPin) || !strings.Contains(first,"--decision reject --projection-hash "+oldPin) { t.Fatalf("missing copy-safe commands: %s",first) }
	second := captureStdout(t, func() { reviewErr = runTriage([]string{"--record-decision",dir,"--actor","bob","--answer","deployment_perimeter=cluster-internal"}) })
	if reviewErr != nil || !strings.Contains(second,"action=ACCEPT_ENVIRONMENTAL_MITIGATION") { t.Fatalf("Bob presentation: %s %v",second,reviewErr) }
	newPin := presentedReviewProjection(t,second)
	if oldPin == newPin { t.Fatal("supersession did not change projection") }
	for _, choice := range []string{"accept","reject"} {
		err := runTriage([]string{"--record-decision",dir,"--actor","alice","--decision",choice,"--projection-hash",oldPin})
		wantExit(t,err,triage.ExitCodeError)
		if !strings.Contains(err.Error(),"projection changed") { t.Fatalf("stale decision not rejected by writer: %v",err) }
	}
	err := runTriage([]string{"--record-decision",dir,"--actor","alice","--decision","accept"})
	wantExit(t,err,triage.ExitCodeError)
	if !strings.Contains(err.Error(),"requires --projection-hash") { t.Fatal(err) }
	if history,err := triage.ReadHumanDecisions(dir,pkg); err != nil || len(history)!=0 { t.Fatalf("stale or unpinned decision persisted: %+v %v",history,err) }
	if err := runTriage([]string{"--record-decision",dir,"--actor","bob","--decision","accept","--projection-hash",newPin}); err != nil { t.Fatal(err) }
	// Explicitly restating every answer is the supported one-step alternative;
	// it uses the selected hash and the same locked writer check.
	if err := runTriage([]string{"--record-decision",dir,"--actor","alice","--answer","deployment_perimeter=public","--decision","reject"}); err != nil { t.Fatal(err) }
	history,err := triage.ReadHumanDecisions(dir,pkg)
	if err != nil || len(history)!=2 { t.Fatalf("valid pinned/one-step decisions: %+v %v",history,err) }
}

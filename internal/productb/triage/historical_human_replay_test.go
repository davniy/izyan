package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This fixture deliberately records the prior v2/v3 contract, with its own
// prompt/response/assessment/package pins. It never upgrades historical bytes.
func TestHumanBranchHistoricalV2V3Replay(t *testing.T) {
	ctx := context.Background()
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	var pi PromptInput
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.runDir, PromptInputArtifactName)), &pi); err != nil { t.Fatal(err) }
	pi.System = buildPhase1Prompt(pi.Tools, false)
	pi.PromptHash = PromptHash(pi.System, pi.Messages)
	stored := f.stored
	stored.SchemaVersion = "assessment.v2"
	stored.Audit.PromptHash = pi.PromptHash
	agent := stored
	agent.Audit = nil
	agent.VerdictSource = ""
	agent.FactValidation = ""
	agent.FactValidationDetail = nil
	response, err := json.Marshal(agent)
	if err != nil { t.Fatal(err) }
	stored.Audit.ResponseHash = hashBytes(response)
	stored.Audit.AssessmentHash = canonicalAssessmentHash(stored)
	var raw RawAgentDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.runDir, "raw-agent.json")), &raw); err != nil { t.Fatal(err) }
	raw.PromptHash = pi.PromptHash
	raw.ResponseHash = hashBytes(response)
	raw.Messages[len(raw.Messages)-1].Content = string(response)
	if len(raw.Messages) > 0 && raw.Messages[0].Role == "system" { raw.Messages[0].Content = pi.System }
	s0, err := ReplayStage0(ctx, f.runDir)
	if err != nil { t.Fatal(err) }
	pkg, err := (Composer{historicalReplay: true, RulesetHash: "0707070707070707070707070707070707070707070707070707070707070707", Limits: BudgetConfig{MaxLLMSteps: 32, MaxToolCalls: 128, MaxSourceBytes: 1 << 20, TimeoutSeconds: 900}}).Compose(ctx, s0, stored, *stored.FactValidationDetail, nil)
	if err != nil { t.Fatal(err) }
	for name, value := range map[string]any{PromptInputArtifactName: pi, "raw-agent.json": raw, "assessment.json": stored, "decision.json": pkg} {
		if err := writeJSONAtomic(ctx, filepath.Join(f.runDir, name), value); err != nil { t.Fatal(err) }
	}
	md := renderPhase1DecisionMarkdown(pkg)
	if err := os.WriteFile(filepath.Join(f.runDir, "decision.md"), md, 0o644); err != nil { t.Fatal(err) }
	before := hashTree(t, f.runDir)
	rep, err := PrepareReplay(ctx, f.runDir)
	if err != nil { t.Fatal(err) }
	if rep.Decision == nil || rep.Decision.SchemaVersion != "decision-package.v3" || rep.Assessment.SchemaVersion != "assessment.v2" || rep.Decision.HumanReviewPlan != nil { t.Fatalf("history upgraded: %+v", rep.Decision) }
	if _, err := DecodeAssessment(string(response), f.stored.FindingID); err == nil { t.Fatal("historical response re-admitted live") }
	if err := rep.Decision.Validate(); err == nil { t.Fatal("historical package admitted live") }
	art, err := (ArtifactWriter{Clock: replayClockB}).WriteReplay(ctx, t.TempDir(), rep)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(md, mustRead(t, art.DecisionMarkdownPath)) { t.Fatal("historical markdown changed") }
	after := hashTree(t, f.runDir)
	for name, hash := range before { if after[name] != hash { t.Fatalf("source history changed: %s", name) } }
}

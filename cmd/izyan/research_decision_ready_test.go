package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/flow"
	"github.com/davniy/izyan/internal/research"
)

func TestDecisionReadyFlagConflicts(t *testing.T) {
	dir := t.TempDir()
	base := []string{
		"--snapshot", dir, "--cve", "CVE-2024-32473",
		"--advisory-file", dir + "/adv.json", "--output-dir", dir + "/out",
	}
	cases := [][]string{
		// replay-agent-turn is the legacy one-turn replay: it does not
		// combine with the R6 route.
		{"--decision-ready", "--replay-agent-turn", dir + "/old"},
		// decision-run replay never touches a model.
		{"--replay-decision-run", dir + "/old", "--deterministic-only"},
	}
	for _, extra := range cases {
		err := runResearch(append(append([]string{}, base...), extra...))
		if err == nil {
			t.Fatalf("%v: expected flag conflict error", extra)
		}
		if _, statErr := os.Stat(dir + "/out"); statErr == nil {
			t.Fatalf("%v: output dir created before flag rejection", extra)
		}
	}
	// Ordinary research remains offline without a compatibility switch.
	if err := runResearch(base); err != nil && strings.Contains(err.Error(), "--decision-ready") {
		t.Fatalf("offline path tripped on historical mode flags: %v", err)
	}
}

// The decision-ready run manifest carries the flow pins: termination,
// per-turn prompt pins, and the artifact digests.
func TestDecisionReadyRunManifest(t *testing.T) {
	dir := t.TempDir()
	o := researchOpts{decisionReady: true}
	rec := &research.DecisionRunRecord{
		Result:    &flow.Result{Termination: flow.TermPlannerFailure, Reason: "no planner", Ready: false},
		Objective: "test objective",
		Turns: []research.AgentTurnMetadata{{
			Role: "plan", Ordinal: 1, Status: research.AgentFailed,
			PromptPath:   "eval/agent7/prompts/r6-plan-v1.txt",
			PromptSHA256: strings.Repeat("a", 64),
		}},
	}
	report := &research.Report{
		DecisionArtifact: &research.DecisionArtifact{
			ProposedDisposition: research.DispositionHoldUnknown,
			ReplayAndPolicyPins: research.ReplayAndPolicyPins{
				PromptDigest:   strings.Repeat("b", 64),
				CatalogDigests: map[string]string{"checks": strings.Repeat("c", 64)},
			},
		},
	}
	lane := &research.LaneResult{}
	rec.Lane = lane
	if err := writeDecisionRunManifest(dir, o, "run-x", time.Now(), report, rec); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	dr, ok := m["decision_ready"].(map[string]any)
	if !ok {
		t.Fatalf("manifest missing decision_ready: %v", m)
	}
	if dr["termination"] != "PLANNER_FAILURE" {
		t.Fatalf("termination %v", dr["termination"])
	}
	turns, ok := dr["turns"].([]any)
	if !ok || len(turns) != 1 {
		t.Fatalf("turns %v", dr["turns"])
	}
	t0 := turns[0].(map[string]any)
	if t0["prompt_path"] != "eval/agent7/prompts/r6-plan-v1.txt" ||
		t0["prompt_sha256"] != strings.Repeat("a", 64) {
		t.Fatalf("turn pins %v", t0)
	}
	if dr["prompt_digest"] != strings.Repeat("b", 64) {
		t.Fatalf("prompt_digest %v", dr["prompt_digest"])
	}
	if _, ok := m["options"].(map[string]any)["decision_ready"]; !ok {
		t.Fatal("options missing decision_ready marker")
	}
	// A legacy run must not grow the R6 members.
	m2 := optionsManifest(researchOpts{})
	if _, ok := m2["decision_ready"]; ok {
		t.Fatal("legacy options manifest carries decision_ready")
	}
}

func TestDecisionReadyArtifactCredentialRedaction(t *testing.T) {
	o := researchOpts{artifactURL: "https://user:pass@example.test/release.zip?token=fixture", artifactCredsEnv: "FIXTURE_CREDENTIALS", artifactCache: "/tmp/r6-cache"}
	m := optionsManifest(o)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, secret := range []string{"user:pass", "token=fixture", "pass"} {
		if strings.Contains(s, secret) {
			t.Fatalf("credential material leaked into options manifest: %q", secret)
		}
	}
	if !strings.Contains(s, "https://example.test/release.zip") || !strings.Contains(s, "FIXTURE_CREDENTIALS") {
		t.Fatalf("sanitized artifact option projection = %s", s)
	}
}

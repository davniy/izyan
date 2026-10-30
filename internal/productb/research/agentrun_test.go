package research

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeArtifacts drops fixture files into a fake run directory.
func writeArtifacts(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRecoverAgentAnswer_StderrLastResort is the dominant pilot failure:
// the export parses but the assistant message has no parts (agent died on
// a provider error), stdout is empty, session-list is bare metadata. The
// stderr log is the last source and must become raw_agent_output.txt so
// the answer — and its diagnosis — is never lost.
func TestRecoverAgentAnswer_StderrLastResort(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"opencode-export.json": `{"info":{},"messages":[{"info":{"role":"user"},"parts":[{"type":"text","text":"prompt"}]},{"info":{"role":"assistant"},"parts":[]}]}`,
		"opencode-stdout.txt":  "",
		"session-list.json":    `[{"id":"ses_x","title":"New session","updated":1,"created":1,"projectId":"global","directory":"/work"}]`,
		"opencode-stderr.log":  "Database migration complete.\n\n> build · Qwen/Qwen3.6-35B-A3B\n\nError: unable to verify the first certificate\n",
	})
	r := &Report{Artifacts: map[string]string{}}
	recoverAgentAnswer(r, runDir)

	raw, err := os.ReadFile(filepath.Join(runDir, "raw_agent_output.txt"))
	if err != nil {
		t.Fatalf("raw_agent_output.txt not written: %v", err)
	}
	if !strings.Contains(string(raw), "unable to verify the first certificate") {
		t.Fatalf("raw answer is not the stderr capture: %q", raw)
	}
	if r.Answer.Source != "opencode-stderr.log" {
		t.Fatalf("source = %q, want opencode-stderr.log", r.Answer.Source)
	}
	if r.Artifacts["raw_answer"] != "raw_agent_output.txt" {
		t.Fatalf("raw_answer artifact not recorded: %v", r.Artifacts)
	}
}

// TestRecoverAgentAnswer_SessionList covers the third source: a session
// listing that embeds export-shaped message content yields the last
// assistant text even when export and stdout are unusable.
func TestRecoverAgentAnswer_SessionList(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"opencode-export.json": `{"info":{},"messages":[]}`,
		"session-list.json": `[
		  {"id":"ses_a","title":"New session","created":1},
		  {"id":"ses_b","messages":[{"info":{"role":"assistant"},"parts":[{"type":"text","text":"{\"category\":\"uncertain\",\"reasoning\":\"from session list\"}"}]}]}
		]`,
	})
	r := &Report{Artifacts: map[string]string{}}
	recoverAgentAnswer(r, runDir)

	raw, err := os.ReadFile(filepath.Join(runDir, "raw_agent_output.txt"))
	if err != nil {
		t.Fatalf("raw_agent_output.txt not written: %v", err)
	}
	if !strings.Contains(string(raw), "from session list") {
		t.Fatalf("raw answer is not the session-list text: %q", raw)
	}
	if r.Answer.Source != "session-list.json" {
		t.Fatalf("source = %q, want session-list.json", r.Answer.Source)
	}
}

// TestRecoverAgentAnswer_StdoutPreferredOverFallbacks keeps the existing
// order: a usable stdout capture wins over session-list and stderr.
func TestRecoverAgentAnswer_StdoutPreferred(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"opencode-stdout.txt": "the agent printed {\"category\":\"vulnerable\",\"reasoning\":\"stdout\"}",
		"opencode-stderr.log": "noise",
		"session-list.json":   `[{"id":"ses_a"}]`,
	})
	r := &Report{Artifacts: map[string]string{}}
	recoverAgentAnswer(r, runDir)

	raw, err := os.ReadFile(filepath.Join(runDir, "raw_agent_output.txt"))
	if err != nil {
		t.Fatalf("raw_agent_output.txt not written: %v", err)
	}
	if !strings.Contains(string(raw), "stdout") {
		t.Fatalf("raw answer is not the stdout capture: %q", raw)
	}
	if r.Answer.Source != "opencode-stdout.txt" {
		t.Fatalf("source = %q, want opencode-stdout.txt", r.Answer.Source)
	}
}

// TestRecoverAgentAnswer_NothingRecovered asserts the diagnostic duty:
// when no artifact yields text the run reason must enumerate what was
// pulled, its sizes, the exit code and the stderr tail — never a bare
// "file not found" downstream.
func TestRecoverAgentAnswer_NothingRecovered(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"opencode-export.json": `{"info":{},"messages":[]}`,
		"opencode-stdout.txt":  "",
		"opencode-stderr.log":  "",
		"session-list.json":    `[{"id":"ses_a","title":"New session"}]`,
		"opencode-exit":        "124\n",
	})
	ec := 124
	r := &Report{Artifacts: map[string]string{}, Run: RunInfo{ContainerExit: &ec}}
	recoverAgentAnswer(r, runDir)

	if fileExists(filepath.Join(runDir, "raw_agent_output.txt")) {
		t.Fatal("raw_agent_output.txt must not be invented when no source yields text")
	}
	if !strings.Contains(r.Run.Reason, "artifacts:") ||
		!strings.Contains(r.Run.Reason, "session-list.json") ||
		!strings.Contains(r.Run.Reason, "container exit 124") {
		t.Fatalf("run reason is not diagnostic: %q", r.Run.Reason)
	}
	if _, ok := r.Artifacts["raw_answer"]; ok {
		t.Fatal("raw_answer artifact recorded without an answer")
	}
}

// TestAnalyzeAnswer_UnreadableIsDiagnostic covers the full unreadable
// path: raw missing → parse_error carries the artifact inventory so the
// report explains itself.
func TestAnalyzeAnswer_UnreadableIsDiagnostic(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"opencode-export.json": `{"info":{},"messages":[]}`,
		"opencode-stderr.log":  "Error: certificate verify failed\n",
	})
	ec := 1
	r := &Report{
		Run: RunInfo{ContainerExit: &ec},
		Analysis: Analysis{
			ConfirmedFacts: []Fact{},
			Assumptions:    ExtractionList{State: "not_assessed"},
			Unknowns:       ExtractionList{State: "not_assessed"},
		},
	}
	analyzeAnswer(Options{SnapshotDir: t.TempDir()}, r, runDir)

	if r.Answer.Parsed || r.Answer.CategoryLabel != "unavailable" {
		t.Fatalf("answer = %+v", r.Answer)
	}
	for _, want := range []string{"raw answer unreadable", "opencode-export.json", "container exit 1", "certificate verify failed"} {
		if !strings.Contains(r.Answer.ParseError, want) {
			t.Fatalf("parse_error missing %q: %q", want, r.Answer.ParseError)
		}
	}
}

// TestSalvageCategory exercises the literal scan: truncated JSON, prose,
// escaped literals and out-of-vocabulary literals.
func TestSalvageCategory(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
		ok              bool
	}{
		{"truncated_json", `{"category": "vulnerable", "reasoning": "the parser panics on malformed input and the call chain rea`, "vulnerable", true},
		{"prose_literal", `Verdict after review: "category": "false_positive". The call never reaches it.`, "false_positive", true},
		{"escaped_literal", `the agent wrote {\"category\": \"uncertain\", \"reasoning\": ...} into the log`, "uncertain", true},
		{"last_valid_wins", `"category": "bogus_value" … "category": "uncertain"`, "uncertain", true},
		{"invalid_value", `"category": "definitely_safe_bro"`, "", false},
		{"no_literal", "no json, no category marker at all", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := salvageCategory(tc.raw)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("salvageCategory(%q) = (%q,%v), want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestAnalyzeAnswer_SalvagedFromTruncatedJSON is the third pilot failure:
// raw exists and is agent output, but no balanced {category, reasoning}
// object survives. The verbatim category literal is recovered and flagged
// as salvaged — never guessed, never silently promoted.
func TestAnalyzeAnswer_SalvagedFromTruncatedJSON(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"raw_agent_output.txt": `{"category": "vulnerable", "reasoning": "The YAML parser panics on malformed events; decode.go reaches an unknown event state and`,
	})
	r := &Report{
		Analysis: Analysis{
			ConfirmedFacts: []Fact{},
			Assumptions:    ExtractionList{State: "not_assessed"},
			Unknowns:       ExtractionList{State: "not_assessed"},
		},
	}
	analyzeAnswer(Options{SnapshotDir: t.TempDir()}, r, runDir)

	if !r.Answer.Parsed || !r.Answer.Salvaged || r.Answer.Category != "vulnerable" {
		t.Fatalf("salvaged answer = %+v", r.Answer)
	}
	if r.Answer.CategoryLabel != "research_judgement" || r.Answer.Reasoning != "" {
		t.Fatalf("salvaged answer must stay a verbatim category without reasoning: %+v", r.Answer)
	}
	if r.Answer.ParseError == "" || !strings.Contains(r.Answer.ParseError, "salvaged") {
		t.Fatalf("salvage must record the original parse failure: %q", r.Answer.ParseError)
	}
	if r.Answer.RawPath != "raw_agent_output.txt" {
		t.Fatalf("raw path not recorded: %+v", r.Answer)
	}
}

// fakeDocker writes a stub docker executable: create echoes a container
// id (or fails when FAKE_DOCKER_CREATE_FAIL is set), start exits with
// FAKE_DOCKER_START_EXIT, cp materializes files from FAKE_DOCKER_ARTIFACTS.
func fakeDocker(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
case "$1" in
  create)
    if [ -n "$FAKE_DOCKER_CREATE_FAIL" ]; then echo "cannot connect to the docker daemon" >&2; exit 1; fi
    echo cid123 ;;
  start)
    exit "${FAKE_DOCKER_START_EXIT:-0}" ;;
  cp)
    name="${2##*/}"
    src="$FAKE_DOCKER_ARTIFACTS/$name"
    if [ -f "$src" ]; then cp "$src" "$3"; else exit 1; fi ;;
  rm|kill) exit 0 ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// TestLaunchAgent_DockerCreateErrorHasReason is the second pilot failure:
// a run that dies before any artifact exists (docker daemon down) used to
// leave run.reason empty. The deferred fill guarantees a diagnostic.
func TestLaunchAgent_DockerCreateErrorHasReason(t *testing.T) {
	t.Setenv("FAKE_DOCKER_CREATE_FAIL", "1")
	runDir := t.TempDir()
	r := &Report{Artifacts: map[string]string{}, Run: RunInfo{Argv: []string{"docker", "create", "img"}}}
	launchAgent(context.Background(), Options{DockerBin: fakeDocker(t)}, r, runDir)

	if r.Run.Status != "error" {
		t.Fatalf("status = %q, want error", r.Run.Status)
	}
	if !strings.Contains(r.Run.Error, "cannot connect to the docker daemon") {
		t.Fatalf("run.error lost the docker message: %q", r.Run.Error)
	}
	if r.Run.Reason == "" {
		t.Fatal("run.reason left empty on a technical failure")
	}
}

// TestLaunchAgent_StartFailureStillRecovers exercises the full artifact
// path: docker start fails, artifacts are pulled anyway, stderr becomes
// the raw answer and run.error gains the container-side diagnosis.
func TestLaunchAgent_StartFailureStillRecovers(t *testing.T) {
	artDir := t.TempDir()
	writeArtifacts(t, artDir, map[string]string{
		"opencode-stderr.log": "Error: unable to verify the first certificate\n",
		"opencode-exit":       "3\n",
	})
	t.Setenv("FAKE_DOCKER_ARTIFACTS", artDir)
	t.Setenv("FAKE_DOCKER_START_EXIT", "3")
	runDir := t.TempDir()
	r := &Report{Artifacts: map[string]string{}, Run: RunInfo{Argv: []string{"docker", "create", "img"}}}
	launchAgent(context.Background(), Options{DockerBin: fakeDocker(t)}, r, runDir)

	if r.Run.Status != "error" {
		t.Fatalf("status = %q, want error", r.Run.Status)
	}
	if !strings.Contains(r.Run.Error, "unable to verify the first certificate") ||
		!strings.Contains(r.Run.Error, "opencode exit 3") {
		t.Fatalf("run.error not enriched from artifacts: %q", r.Run.Error)
	}
	if r.Run.Reason == "" {
		t.Fatal("run.reason left empty on a technical failure")
	}
	raw, err := os.ReadFile(filepath.Join(runDir, "raw_agent_output.txt"))
	if err != nil || !strings.Contains(string(raw), "certificate") {
		t.Fatalf("stderr not recovered as raw answer (err=%v)", err)
	}
	if r.Answer.Source != "opencode-stderr.log" {
		t.Fatalf("source = %q, want opencode-stderr.log", r.Answer.Source)
	}
}

// TestAnalyzeAnswer_NoSalvageWithoutLiteral ensures the scan never invents
// a category: prose without a valid literal stays unavailable.
func TestAnalyzeAnswer_NoSalvageWithoutLiteral(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"raw_agent_output.txt": "I checked everything and the product is clearly safe, trust me.",
	})
	r := &Report{
		Analysis: Analysis{
			ConfirmedFacts: []Fact{},
			Assumptions:    ExtractionList{State: "not_assessed"},
			Unknowns:       ExtractionList{State: "not_assessed"},
		},
	}
	analyzeAnswer(Options{SnapshotDir: t.TempDir()}, r, runDir)

	if r.Answer.Parsed || r.Answer.Salvaged || r.Answer.Category != "" {
		t.Fatalf("uncategorised prose must stay unavailable: %+v", r.Answer)
	}
	if r.Answer.ParseError == "" {
		t.Fatal("parse error not recorded")
	}
}

// TestEnrichRunError covers the silent technical failure: a run that ended
// in error/timeout must carry the opencode exit code and the artifact
// tails so the report is diagnosable without re-running anything.
func TestEnrichRunError(t *testing.T) {
	runDir := t.TempDir()
	writeArtifacts(t, runDir, map[string]string{
		"opencode-exit":          "124\n",
		"opencode-stderr.log":    "still running when killed\n",
		"opencode-stdout.txt":    "partial output line\n",
		"opencode-export.stderr": "export: session not found\n",
	})
	r := &Report{Run: RunInfo{Status: "error", Error: "docker start: exit 1: boom"}}
	enrichRunError(r, runDir)

	for _, want := range []string{"opencode exit 124", "still running when killed", "partial output line", "session not found"} {
		if !strings.Contains(r.Run.Error, want) {
			t.Fatalf("run.error missing %q: %q", want, r.Run.Error)
		}
	}

	// A clean run is never touched.
	clean := &Report{Run: RunInfo{Status: "ok", Error: ""}}
	enrichRunError(clean, runDir)
	if clean.Run.Error != "" {
		t.Fatalf("ok run gained an error: %q", clean.Run.Error)
	}
}

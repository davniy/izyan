package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/llm"
)

// replayFixture holds one recorded triage run plus the pieces tests assert on.
type replayFixture struct {
	repoDir    string
	runDir     string
	client     *scriptedChat
	stored     Assessment       // composed assessment as written to assessment.json
	manifest   SnapshotManifest // the snapshot the run pinned
	promptHash string           // prompt hash computed by the original run
}

// newReplayRepo creates a source tree the snapshot builder can pin.
func newReplayRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), linedFile(60))
	return dir
}

// newReplayGitRepo creates a git-backed source tree with tag v1 so revision
// pinning and re-resolution can be exercised.
func newReplayGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), linedFile(60))
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-q", "-m", "init")
	gitCmd(t, dir, "tag", "v1")
	return dir
}

// recordReplayRun produces a complete, realistic run directory without a real
// LLM: a scripted chat answer is decoded by the real runner, validated by the
// real fact gate and persisted by the real artifact writer.
func recordReplayRun(t *testing.T, repoDir, outDir, model string, builderNow, clock func() time.Time) replayFixture {
	t.Helper()
	return recordReplayRunTarget(t, Target{Repository: repoDir}, outDir, model, builderNow, clock)
}

// recordReplayRunTarget records a run for an arbitrary finding target (e.g.
// with a pinned revision); the working tree lives at target.Repository.
func recordReplayRunTarget(t *testing.T, target Target, outDir, model string, builderNow, clock func() time.Time) replayFixture {
	t.Helper()
	ctx := context.Background()
	inputJSON, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     "scanner-123",
		Vulnerability: Vulnerability{IDs: []string{"CVE-2025-1234"}},
		Target:        target,
	})
	if err != nil {
		t.Fatal(err)
	}
	repoDir := target.Repository
	findings, err := ParseFindings(strings.NewReader(string(inputJSON)))
	if err != nil {
		t.Fatalf("ParseFindings: %v", err)
	}
	in := findings[0]
	manifest, err := LocalSnapshotBuilder{Now: builderNow}.Build(ctx, in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	agent := Assessment{
		SchemaVersion:  AssessmentSchemaVersion,
		FindingID:      in.Finding.FindingID,
		Verdict:        VerdictNotExploitable,
		Summary:        "vulnerable code path is absent",
		Claims:         []Claim{refClaim("c1", "e1")},
		Evidence:       []EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:10-20"}},
		ProposedAction: closeAction("c1"),
	}
	agentJSON, err := json.Marshal(agent)
	if err != nil {
		t.Fatal(err)
	}
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: string(agentJSON)}}}
	tools := &ReadOnlyTools{Snapshot: manifest, Finding: in}
	run, err := AgentRunner{Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 2}}.Run(ctx, in, manifest)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	fv := FactGate{}.Validate(ctx, in, manifest, run.Assessment)
	if fv.Status != ValidationComplete {
		t.Fatalf("fixture gate = %s, want COMPLETE (%+v)", fv.Status, fv)
	}
	assessment := run.Assessment
	assessment.FactValidation = fv.Status
	assessment.FactValidationDetail = &fv
	w := ArtifactWriter{Clock: clock, Model: model, ToolVersions: map[string]string{"izyan": "test"}}
	art, err := w.Write(ctx, outDir, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var stored Assessment
	data, err := os.ReadFile(art.AssessmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	return replayFixture{
		repoDir:    repoDir,
		runDir:     art.RootDir,
		client:     client,
		stored:     stored,
		manifest:   manifest,
		promptHash: run.PromptHash,
	}
}

// hashTree hashes every file under dir, keyed by slash-relative path.
func hashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out[filepath.ToSlash(rel)] = sha256Hex(t, data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// copyRunDir duplicates a run directory so a test can damage the copy.
func copyRunDir(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestReplayRunReproducesAssessment(t *testing.T) {
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
	if f.stored.Audit == nil {
		t.Fatal("stored assessment has no audit block")
	}
	callsBefore := f.client.calls

	got, err := ReplayRun(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("ReplayRun: %v", err)
	}
	if f.client.calls != callsBefore {
		t.Fatalf("replay invoked the chat client: %d -> %d calls", callsBefore, f.client.calls)
	}
	if got.Audit == nil {
		t.Fatal("replayed assessment has no audit block")
	}
	want := f.stored.Audit
	if got.Audit.FindingHash != want.FindingHash ||
		got.Audit.SnapshotHash != want.SnapshotHash ||
		got.Audit.PromptHash != want.PromptHash ||
		got.Audit.ResponseHash != want.ResponseHash ||
		got.Audit.AssessmentHash != want.AssessmentHash {
		t.Fatalf("audit hashes differ:\n got %+v\nwant %+v", got.Audit, want)
	}
	if got.Audit.PromptHash != f.promptHash {
		t.Fatalf("prompt_hash = %s, original run recorded %s", got.Audit.PromptHash, f.promptHash)
	}
	if got.Verdict != f.stored.Verdict ||
		got.FactValidation != f.stored.FactValidation {
		t.Fatalf("replayed outcome %+v differs from stored verdict=%s validation=%s",
			got, f.stored.Verdict, f.stored.FactValidation)
	}
	if got.FactValidationDetail == nil || len(got.FactValidationDetail.References) != 1 ||
		got.FactValidationDetail.References[0].EvidenceID != "e1" {
		t.Fatalf("replayed assessment lost fact validation detail: %+v", got.FactValidationDetail)
	}
}

func TestReplayRunLeavesSourceUntouched(t *testing.T) {
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
	before := hashTree(t, f.runDir)
	if _, err := ReplayRun(context.Background(), f.runDir); err != nil {
		t.Fatalf("ReplayRun: %v", err)
	}
	after := hashTree(t, f.runDir)
	if len(before) != len(after) {
		t.Fatalf("source run file set changed: %d -> %d", len(before), len(after))
	}
	for name, sum := range before {
		if after[name] != sum {
			t.Fatalf("source run file %s changed during replay", name)
		}
	}
}

func TestReplayRunMissingInputs(t *testing.T) {
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)

	t.Run("no such directory", func(t *testing.T) {
		if _, err := ReplayRun(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("expected error for missing run directory")
		}
	})
	for _, name := range []string{"input.json", "snapshot.json", "raw-agent.json", "assessment.json"} {
		t.Run("missing "+name, func(t *testing.T) {
			dir := copyRunDir(t, f.runDir)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			got, err := ReplayRun(context.Background(), dir)
			if err == nil {
				t.Fatalf("expected technical error for missing %s", name)
			}
			if got.Verdict != "" {
				t.Fatalf("replay produced a verdict %q from a broken run", got.Verdict)
			}
		})
	}
}

// TestReplaySnapshotDrift: the recorded-manifest drift check lives in
// VerifySnapshotDrift — an explicit opt-in call, outside the offline
// replay contract. A changed or deleted source tree is a drift error
// there, while the same recorded run replays cleanly offline.
func TestReplaySnapshotDrift(t *testing.T) {
	t.Run("source file changed after the run", func(t *testing.T) {
		f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
		writeFile(t, filepath.Join(f.repoDir, "main.go"), "package changed\n// the pinned content is gone\n")
		if err := VerifySnapshotDrift(context.Background(), f.manifest); err == nil {
			t.Fatal("expected fail-closed error on snapshot drift")
		} else if !strings.Contains(err.Error(), "drift") && !strings.Contains(err.Error(), "snapshot") {
			t.Fatalf("error should name the snapshot drift, got: %v", err)
		}
		if _, err := ReplayRun(context.Background(), f.runDir); err != nil {
			t.Fatalf("offline replay must not read the live tree: %v", err)
		}
	})
	t.Run("source file deleted after the run", func(t *testing.T) {
		f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
		if err := os.Remove(filepath.Join(f.repoDir, "main.go")); err != nil {
			t.Fatal(err)
		}
		if err := VerifySnapshotDrift(context.Background(), f.manifest); err == nil {
			t.Fatal("expected fail-closed error when a pinned file disappeared")
		}
		if _, err := ReplayRun(context.Background(), f.runDir); err != nil {
			t.Fatalf("offline replay must not read the live tree: %v", err)
		}
	})
	t.Run("stored input drifted", func(t *testing.T) {
		dir := copyRunDir(t, recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA).runDir)
		path := filepath.Join(dir, "input.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplayRun(context.Background(), dir); err == nil {
			t.Fatal("expected error when input.json no longer matches recorded input_hash")
		}
	})
	t.Run("stored assessment tampered", func(t *testing.T) {
		dir := copyRunDir(t, recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA).runDir)
		path := filepath.Join(dir, "assessment.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var a Assessment
		if err := json.Unmarshal(data, &a); err != nil {
			t.Fatal(err)
		}
		a.Summary = "rewritten after the run"
		out, err := json.MarshalIndent(a, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplayRun(context.Background(), dir); err == nil {
			t.Fatal("expected error when assessment.json no longer matches its recorded hash")
		}
	})
}

func TestAssessmentHashReproducible(t *testing.T) {
	repo := newReplayRepo(t)
	// Identical input/snapshot/prompt inputs; only the output directory and
	// the writer clocks differ.
	f1 := recordReplayRun(t, repo, t.TempDir(), "test-model", replayClockA, replayClockA)
	f2 := recordReplayRun(t, repo, t.TempDir(), "test-model", replayClockA, replayClockB)
	a1, a2 := f1.stored.Audit, f2.stored.Audit
	if a1 == nil || a2 == nil {
		t.Fatal("missing audit block")
	}
	if a1.FindingHash != a2.FindingHash {
		t.Fatalf("finding_hash differs for identical input: %s vs %s", a1.FindingHash, a2.FindingHash)
	}
	if a1.SnapshotHash != a2.SnapshotHash {
		t.Fatalf("snapshot_hash differs for identical tree: %s vs %s", a1.SnapshotHash, a2.SnapshotHash)
	}
	if a1.PromptHash != a2.PromptHash {
		t.Fatalf("prompt_hash differs for identical prompt: %s vs %s", a1.PromptHash, a2.PromptHash)
	}
	if a1.AssessmentHash != a2.AssessmentHash {
		t.Fatalf("assessment_hash differs across output dirs/timestamps: %s vs %s", a1.AssessmentHash, a2.AssessmentHash)
	}

	// A replay of the first run re-derives the identical assessment hash.
	rep, err := ReplayRun(context.Background(), f1.runDir)
	if err != nil {
		t.Fatalf("ReplayRun: %v", err)
	}
	if rep.Audit.AssessmentHash != a1.AssessmentHash {
		t.Fatalf("replay assessment_hash = %s, recorded %s", rep.Audit.AssessmentHash, a1.AssessmentHash)
	}
}

func TestWriteReplayReport(t *testing.T) {
	repo := newReplayRepo(t)
	f := recordReplayRun(t, repo, t.TempDir(), "test-model", replayClockA, replayClockA)
	before := hashTree(t, f.runDir)

	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	outDir := t.TempDir()
	w := ArtifactWriter{Clock: replayClockB}
	art, err := w.WriteReplay(context.Background(), outDir, rep)
	if err != nil {
		t.Fatalf("WriteReplay: %v", err)
	}
	outCanon, err := filepath.EvalSymlinks(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if art.RootDir == f.runDir || !strings.HasPrefix(art.RootDir, outCanon+string(filepath.Separator)) {
		t.Fatalf("replay report written to %q, want a new directory under %q", art.RootDir, outDir)
	}
	for _, name := range []string{"input.json", "snapshot.json", "raw-agent.json", "assessment.json", "assessment.md", "replay.json", filepath.Join("audit", "events.jsonl")} {
		if info, serr := os.Stat(filepath.Join(art.RootDir, name)); serr != nil || info.IsDir() {
			t.Fatalf("replay artifact %s missing: %v", name, serr)
		}
	}

	var doc ReplayDocument
	data, err := os.ReadFile(filepath.Join(art.RootDir, "replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != ReplaySchemaVersion {
		t.Fatalf("replay.json schema = %q", doc.SchemaVersion)
	}
	if doc.RerenderOf == "" || doc.RerenderOf != rep.SourceDir {
		t.Fatalf("rerender_of = %q, want %q", doc.RerenderOf, rep.SourceDir)
	}
	if doc.SourceAssessmentHash != f.stored.Audit.AssessmentHash {
		t.Fatalf("source_assessment_hash = %q, want %q", doc.SourceAssessmentHash, f.stored.Audit.AssessmentHash)
	}
	if !doc.AssessmentHashMatch || doc.AssessmentHash != rep.Assessment.Audit.AssessmentHash {
		t.Fatalf("unexpected replay hash record: %+v", doc)
	}

	// The re-rendered assessment is byte-identical to the stored one when
	// composition inputs did not change.
	newAssessment, err := os.ReadFile(art.AssessmentPath)
	if err != nil {
		t.Fatal(err)
	}
	oldAssessment, err := os.ReadFile(filepath.Join(f.runDir, "assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(newAssessment) != string(oldAssessment) {
		t.Fatal("re-rendered assessment.json differs from the stored one")
	}

	// The original run directory was not modified.
	after := hashTree(t, f.runDir)
	for name, sum := range before {
		if after[name] != sum {
			t.Fatalf("source run file %s changed", name)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("source run file count changed: %d -> %d", len(before), len(after))
	}
}

func TestWriteReplayRefusesOutputInsideSourceRun(t *testing.T) {
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	inside := filepath.Join(f.runDir, "nested-out")
	if _, err := (ArtifactWriter{}).WriteReplay(context.Background(), inside, rep); err == nil {
		t.Fatal("expected error when --out resolves inside the source run directory")
	}
	if info, serr := os.Stat(inside); serr == nil && info.IsDir() {
		// The refused write may have created the outDir itself; anything
		// beyond that means the source was touched.
		if entries, rerr := os.ReadDir(inside); rerr == nil && len(entries) > 0 {
			t.Fatal("refused replay wrote artifacts inside the source run")
		}
	}
}

// TestReplayEmptyRawMessages covers corrupted raw-agent.json: zero or absent
// messages is a technical error, never a panic indexing the last message.
func TestReplayEmptyRawMessages(t *testing.T) {
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
	for _, name := range []string{"absent", "empty"} {
		t.Run(name, func(t *testing.T) {
			dir := copyRunDir(t, f.runDir)
			var doc map[string]any
			if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "raw-agent.json")), &doc); err != nil {
				t.Fatal(err)
			}
			if name == "absent" {
				delete(doc, "messages")
			} else {
				doc["messages"] = []any{}
			}
			out, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "raw-agent.json"), out, 0o644); err != nil {
				t.Fatal(err)
			}
			got, rerr := ReplayRun(context.Background(), dir)
			if rerr == nil {
				t.Fatal("expected technical error for raw-agent.json without messages")
			}
			if !strings.Contains(rerr.Error(), "assistant") {
				t.Fatalf("error should name the missing assistant response, got: %v", rerr)
			}
			if got.Verdict != "" {
				t.Fatalf("corrupted run produced a verdict %q instead of a technical error", got.Verdict)
			}
		})
	}
}

// TestReplayRevisionDrift: a pinned revision is checked two ways — the
// recorded manifest must carry resolved_revision (offline, data check) and
// the live ref still pointing at it is the explicit VerifySnapshotDrift
// check. Replay itself never re-resolves the ref.
func TestReplayRevisionDrift(t *testing.T) {
	target := Target{Repository: "", Revision: "v1"}

	t.Run("moved tag", func(t *testing.T) {
		repo := newReplayGitRepo(t)
		target.Repository = repo
		f := recordReplayRunTarget(t, target, t.TempDir(), "test-model", replayClockA, replayClockA)
		if _, err := ReplayRun(context.Background(), f.runDir); err != nil {
			t.Fatalf("ReplayRun before drift: %v", err)
		}

		gitCmd(t, repo, "commit", "-q", "--allow-empty", "-m", "move tag")
		gitCmd(t, repo, "tag", "-f", "v1")

		// A moved tag is live drift: the explicit drift check fails, while
		// offline replay still reproduces the recorded run — it never
		// resolves the ref again.
		err := VerifySnapshotDrift(context.Background(), f.manifest)
		if err == nil {
			t.Fatal("expected drift error when the pinned tag moved")
		}
		if !strings.Contains(err.Error(), "revision") {
			t.Fatalf("error should name the revision drift, got: %v", err)
		}
		if _, rerr := ReplayRun(context.Background(), f.runDir); rerr != nil {
			t.Fatalf("offline replay must not re-resolve the moved tag: %v", rerr)
		}
	})

	t.Run("manifest without resolved_revision", func(t *testing.T) {
		repo := newReplayGitRepo(t)
		target.Repository = repo
		f := recordReplayRunTarget(t, target, t.TempDir(), "test-model", replayClockA, replayClockA)

		dir := copyRunDir(t, f.runDir)
		var doc map[string]any
		if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "snapshot.json")), &doc); err != nil {
			t.Fatal(err)
		}
		delete(doc, "resolved_revision")
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "snapshot.json"), out, 0o644); err != nil {
			t.Fatal(err)
		}
		got, rerr := ReplayRun(context.Background(), dir)
		if rerr == nil {
			t.Fatal("expected fail-closed error for a manifest without resolved_revision")
		}
		if !strings.Contains(rerr.Error(), "resolved_revision") {
			t.Fatalf("error should name resolved_revision, got: %v", rerr)
		}
		if got.Verdict != "" {
			t.Fatalf("old manifest produced a verdict %q instead of a technical error", got.Verdict)
		}
	})
}

// TestReplayRestoresObservationIndex: a det:<id> evidence reference is
// verifiable at replay time because the observation index is rebuilt from
// the recorded audit/events.jsonl — the same id → data sha256 binding the
// run wrote. Without the audit log the reference degrades to UNAVAILABLE,
// not a technical error.
func TestReplayRestoresObservationIndex(t *testing.T) {
	ctx := context.Background()
	repoDir := newReplayRepo(t)
	outDir := t.TempDir()
	inputJSON, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     "scanner-123",
		Vulnerability: Vulnerability{IDs: []string{"CVE-2025-1234"}},
		Target:        Target{Repository: repoDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ParseFindings(strings.NewReader(string(inputJSON)))
	if err != nil {
		t.Fatalf("ParseFindings: %v", err)
	}
	in := findings[0]
	manifest, err := LocalSnapshotBuilder{Now: replayClockA}.Build(ctx, in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	fake := &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
		return &evidencetools.Observation{
			ID: "ev-1", Tool: name, Fact: "fake complete fact", Scope: "fake scope",
			Completeness: evidencetools.CompletenessComplete,
			ToolStatus:   evidencetools.StatusOK,
			Data:         map[string]any{"echo": name},
		}, nil
	}}
	tools := &ToolSet{Parts: []ToolExecutor{
		&ReadOnlyTools{Snapshot: manifest, Finding: in},
		&DeterministicTools{Caller: fake, Catalog: CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog())},
	}}
	agent := Assessment{
		SchemaVersion:  AssessmentSchemaVersion,
		FindingID:      in.Finding.FindingID,
		Verdict:        VerdictNotExploitable,
		Summary:        "deterministic check found no callers",
		Claims:         []Claim{refClaim("c1", "e1")},
		Evidence:       []EvidenceRef{{ID: "e1", Kind: "observation", Locator: "det:det-0001"}},
		ProposedAction: closeAction("c1"),
	}
	agentJSON, err := json.Marshal(agent)
	if err != nil {
		t.Fatal(err)
	}
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: "c1", Type: "function", Function: llm.FunctionCall{Name: "find_symbol", Arguments: `{"symbol":{"name":"f"}}`}}}},
		{Role: "assistant", Content: string(agentJSON)},
	}}
	run, err := AgentRunner{Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 4}}.Run(ctx, in, manifest)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	fv := FactGate{Observations: ObservationIndex(tools.AuditEvents())}.Validate(ctx, in, manifest, run.Assessment)
	if fv.Status != ValidationComplete {
		t.Fatalf("fixture gate = %s, want COMPLETE (%+v)", fv.Status, fv)
	}
	assessment := run.Assessment
	assessment.FactValidation = fv.Status
	assessment.FactValidationDetail = &fv
	events := append(
		[]AuditEvent{{Type: AuditEventRunStarted, Status: "ok"}},
		ToolAuditEvents(tools.AuditEvents(), time.Now().UTC())...,
	)
	w := ArtifactWriter{Clock: replayClockA, Model: "test", ToolVersions: map[string]string{"izyan": "test"}}
	art, err := w.Write(ctx, outDir, in, manifest, run, assessment, events, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := ReplayRun(ctx, art.RootDir)
	if err != nil {
		t.Fatalf("ReplayRun: %v", err)
	}
	if got.FactValidation != ValidationComplete {
		t.Fatalf("replayed fact validation = %s, want COMPLETE (%+v)", got.FactValidation, got.FactValidationDetail)
	}
	if got.FactValidationDetail == nil || len(got.FactValidationDetail.References) != 1 ||
		got.FactValidationDetail.References[0].Status != FactValid {
		t.Fatalf("replayed det reference not VALID: %+v", got.FactValidationDetail)
	}

	// Without the audit log the index is empty: the det reference degrades
	// to UNAVAILABLE (PARTIAL), it is never guessed VALID.
	damaged := copyRunDir(t, art.RootDir)
	if err := os.RemoveAll(filepath.Join(damaged, "audit")); err != nil {
		t.Fatal(err)
	}
	got, err = ReplayRun(ctx, damaged)
	if err != nil {
		t.Fatalf("ReplayRun without audit log: %v", err)
	}
	if got.FactValidation != ValidationPartial {
		t.Fatalf("replayed fact validation without audit = %s, want PARTIAL", got.FactValidation)
	}
	if got.FactValidationDetail == nil || len(got.FactValidationDetail.References) != 1 ||
		got.FactValidationDetail.References[0].Status != FactUnavailable {
		t.Fatalf("det reference without audit log: %+v", got.FactValidationDetail)
	}
}

// TestReplayObservationIndexRejectsNonFactStatuses pins the replay-side
// equivalent of the live fact gate: audit-indexed observations with a
// DENIED/ERROR/TIMEOUT/UNSUPPORTED status or PARTIAL/UNKNOWN coverage remain
// unavailable through their canonical obs:/det: citation, never VALID.
func TestReplayObservationIndexRejectsNonFactStatuses(t *testing.T) {
	in, manifest := repoFixture(t)
	runID := "replay-non-fact"
	for _, tc := range []struct {
		name   string
		status string
		cover  string
	}{
		{"denied", string(ToolStatusDenied), "COMPLETE"},
		{"error", string(ToolStatusError), "COMPLETE"},
		{"timeout", string(ToolStatusTimeout), "COMPLETE"},
		{"unsupported", string(ToolStatusUnsupported), "COMPLETE"},
		{"partial", string(ToolStatusOK), "PARTIAL"},
		{"unknown", string(ToolStatusOK), "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o755); err != nil {
				t.Fatal(err)
			}
			event := AuditEvent{Type: AuditEventToolCall, RunID: runID,
				ObservationID: "obs-bad", Tool: "read_file", Status: tc.status,
				Coverage: tc.cover}
			line, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "audit", "events.jsonl"), append(line, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			gate := FactGate{Observations: observationIndexFromAudit(dir, runID, 1)}
			v := gate.Validate(context.Background(), in, manifest, gateAssessment(
				[]Claim{refClaim("c1", "e1")},
				[]EvidenceRef{{ID: "e1", Kind: "observation", Locator: "obs:obs-bad"}},
			))
			if got := checksByEvidence(v)["e1"]; got != FactUnavailable {
				t.Fatalf("status = %q, want UNAVAILABLE (%+v)", got, v.References)
			}
			if v.Status == ValidationComplete {
				t.Fatal("non-fact replay observation must not produce COMPLETE validation")
			}
		})
	}
}

// recordDecisionRun produces a complete decision-bearing run directory
// without a real LLM: Stage 0 artifacts persisted via WriteStage0Artifacts,
// a scripted agent run persisted via Write, then the deterministic composer
// output persisted via WriteDecision. The Stage 0 result is bound to the
// recorded snapshot and intake so every replay check is satisfied offline.
func recordDecisionRun(t *testing.T, repoDir, outDir string, clock func() time.Time, mutate ...func(*Assessment)) replayFixture {
	t.Helper()
	ctx := context.Background()
	target := Target{Repository: repoDir}
	inputJSON, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     "scanner-123",
		Vulnerability: Vulnerability{IDs: []string{"CVE-2025-1234"}},
		Target:        target,
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ParseFindings(strings.NewReader(string(inputJSON)))
	if err != nil {
		t.Fatalf("ParseFindings: %v", err)
	}
	in := findings[0]
	manifest, err := LocalSnapshotBuilder{Now: replayClockA}.Build(ctx, in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	manifest.Materialization = MaterializationMetadata{
		Mode:           MaterializationLocal,
		SourceID:       "service-example",
		RootHash:       manifest.ContentHash,
		ResolvedCommit: manifest.ResolvedRevision,
		CreatedAt:      "2026-10-16T00:00:00Z",
	}

	// Stage 0 result bound to this run: the proposal and finding share the
	// same vulnerability id, the advisory record points at a real frozen
	// file, and materialization provenance matches the manifest.
	s0 := goodStage0()
	s0.Input = in
	s0.Snapshot = manifest
	s0.Source = MaterializedSource{Root: repoDir, Metadata: manifest.Materialization, Cleanup: func() error { return nil }}
	s0.Proposal.VulnerabilityIDs = []string{"CVE-2025-1234"}
	s0.Advisory.ID, s0.Advisory.ResolvedID = "CVE-2025-1234", "CVE-2025-1234"
	advisoryPath := filepath.Join(t.TempDir(), "CVE-2025-1234.json")
	writeFile(t, advisoryPath, `{"id":"CVE-2025-1234","summary":"example advisory"}`)
	s0.Advisory.Path = advisoryPath
	s0.Advisory.SHA256 = sha256Hex(t, mustRead(t, advisoryPath))
	s0.Advisory.Size = int64(len(mustRead(t, advisoryPath)))
	s0.Advisory.FrozenAt = "2026-10-16T00:00:00Z"
	if s0.Resolution != nil {
		s0.Resolution.Vulnerability.ID = "CVE-2025-1234"
		s0.Resolution.Record = s0.Advisory
	}
	for i := range s0.Validation.Fields {
		if s0.Validation.Fields[i].Field == "vulnerability_ids" {
			s0.Validation.Fields[i].Value = "CVE-2025-1234"
		}
	}
	s0.Materials.Materials = []Material{{
		ID: "mat-module-graph", Kind: MaterialModuleGraph, Source: "go list -m all",
		Scope: "build-graph", Availability: MaterialAvailable,
	}}

	w := ArtifactWriter{Clock: clock, Model: "test-model", ToolVersions: map[string]string{"izyan": "test"}}
	if _, err := w.WriteStage0Artifacts(ctx, outDir, s0); err != nil {
		t.Fatalf("WriteStage0Artifacts: %v", err)
	}

	agent := Assessment{
		SchemaVersion:  AssessmentSchemaVersion,
		FindingID:      in.Finding.FindingID,
		Verdict:        VerdictNotExploitable,
		Summary:        "vulnerable code path is absent",
		Claims:         []Claim{refClaim("c1", "e1")},
		Evidence:       []EvidenceRef{{ID: "e1", Kind: "source_span", Locator: "main.go:10-20"}},
		ProposedAction: closeAction("c1"),
	}
	for _, change := range mutate { change(&agent) }
	agentJSON, err := json.Marshal(agent)
	if err != nil {
		t.Fatal(err)
	}
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: string(agentJSON)}}}
	// The agent surface is the Stage 0 view: the intake-normalized input
	// enriched with the resolved advisory — identical to production.
	agentIn := Stage0AgentFinding(in, s0.AdvisoryVulnerability())
	tools := &ReadOnlyTools{Snapshot: manifest, Finding: agentIn, Advisory: s0.AdvisoryProjection()}
	run, err := AgentRunner{Client: client, Tools: tools, Materials: BuildAgentMaterials(s0.Materials), Limits: AgentLimits{MaxSteps: 2}}.Run(ctx, agentIn, manifest)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	fv := FactGate{}.Validate(ctx, agentIn, manifest, run.Assessment)
	if fv.Status != ValidationComplete {
		t.Fatalf("fixture gate = %s, want COMPLETE (%+v)", fv.Status, fv)
	}
	assessment := run.Assessment
	assessment.FactValidation = fv.Status
	assessment.FactValidationDetail = &fv
	art, err := w.Write(ctx, outDir, in, manifest, run, assessment, s0.Events, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	pkg, err := Composer{
		RulesetHash: strings.Repeat("07", 32),
		Limits:      BudgetConfig{MaxLLMSteps: 32, MaxToolCalls: 128, MaxSourceBytes: 1 << 20, TimeoutSeconds: 900},
	}.Compose(ctx, s0, stored, *stored.FactValidationDetail, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := w.WriteDecision(ctx, outDir, pkg); err != nil {
		t.Fatalf("WriteDecision: %v", err)
	}
	return replayFixture{repoDir: repoDir, runDir: art.RootDir, client: client, stored: stored, manifest: manifest, promptHash: run.PromptHash}
}

// TestReplayDecisionReproduces: a recorded decision run replays offline —
// the deterministic composition recomputes to the identical package and the
// replay report carries it into a fresh directory.
func TestReplayDecisionReproduces(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	callsBefore := f.client.calls
	before := hashTree(t, f.runDir)

	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if f.client.calls != callsBefore {
		t.Fatal("replay invoked the chat client")
	}
	if rep.Decision == nil {
		t.Fatal("replay of a decision run produced no decision package")
	}
	var recorded DecisionPackage
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.runDir, "decision.json")), &recorded); err != nil {
		t.Fatal(err)
	}
	wantBytes, err := json.Marshal(recorded)
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := json.Marshal(*rep.Decision)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantBytes, gotBytes) {
		t.Fatalf("recomposed decision package differs:\n got %s\nwant %s", gotBytes, wantBytes)
	}

	repOut := t.TempDir()
	w := ArtifactWriter{Clock: replayClockB}
	art, err := w.WriteReplay(context.Background(), repOut, rep)
	if err != nil {
		t.Fatalf("WriteReplay: %v", err)
	}
	for _, name := range []string{
		"decision.json", "decision.md", "fact-gate.json",
		"intake.json", "intake-proposal.json", "materials.json", "stage0.json",
		"replay.json",
	} {
		if info, serr := os.Stat(filepath.Join(art.RootDir, name)); serr != nil || info.IsDir() {
			t.Fatalf("replay artifact %s missing: %v", name, serr)
		}
	}
	var doc ReplayDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(art.RootDir, "replay.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != ReplaySchemaVersion {
		t.Fatalf("replay.json schema = %q, want %s", doc.SchemaVersion, ReplaySchemaVersion)
	}
	if doc.DecisionHash == "" || !doc.DecisionHashMatch {
		t.Fatalf("replay.json lacks a matching decision hash: %+v", doc)
	}
	// The per-axis comparison covers the human and machine surfaces: replay
	// reproduced the recorded judgment/action and re-derived the premises,
	// support and machine disposition without either side drifting.
	for name, matched := range map[string]bool{
		"judgment": doc.JudgmentMatch, "action": doc.ActionMatch,
		"premises": doc.PremisesMatch, "support": doc.SupportMatch,
		"machine_disposition": doc.MachineDispositionMatch,
	} {
		if !matched {
			t.Fatalf("replay.json reports %s drift on a reproducible run: %+v", name, doc)
		}
	}
	if doc.JudgmentHash == "" || doc.SupportHash == "" || doc.MachineDispositionHash == "" {
		t.Fatalf("replay.json lacks the per-axis hashes: %+v", doc)
	}
	newDecision, err := ValidateDecisionPackageJSON(mustRead(t, filepath.Join(art.RootDir, "decision.json")))
	if err != nil {
		t.Fatalf("replayed decision.json: %v", err)
	}
	if newDecision.MachineDisposition.Recommendation != recorded.MachineDisposition.Recommendation {
		t.Fatalf("replayed recommendation %s, want %s",
			newDecision.MachineDisposition.Recommendation, recorded.MachineDisposition.Recommendation)
	}
	md := string(mustRead(t, filepath.Join(art.RootDir, "decision.md")))
	assertActionCardContract(t, recorded, md)

	// The source run was never modified.
	after := hashTree(t, f.runDir)
	for name, sum := range before {
		if after[name] != sum {
			t.Fatalf("source run file %s changed during replay", name)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("source run file count changed: %d -> %d", len(before), len(after))
	}
}

// TestReplayDecisionDrift: tampering with the decision surface — the
// package itself, its Markdown rendering or any composer input — is a
// technical error, never a re-rendered run.
func TestReplayDecisionDrift(t *testing.T) {
	repo := newReplayRepo(t)
	f := recordDecisionRun(t, repo, t.TempDir(), replayClockA)

	t.Run("decision.json tampered", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		rewriteDecision(t, dir, func(p *DecisionPackage) {
			p.MachineDisposition.Rationale.Summary = "rewritten after the run"
		})
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("tampered decision.json replayed without an error")
		} else if !strings.Contains(err.Error(), "machine admissibility drift") {
			t.Fatalf("tampered machine disposition did not report machine drift: %v", err)
		}
	})

	t.Run("decision.md tampered", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		writeFile(t, filepath.Join(dir, "decision.md"), "# rewritten after the run\n")
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("tampered decision.md replayed without an error")
		}
	})

	t.Run("stage0 resolution drifted", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		var doc map[string]any
		if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "stage0.json")), &doc); err != nil {
			t.Fatal(err)
		}
		doc["config_hash"] = strings.Repeat("ab", 32)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "stage0.json"), string(out))
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("drifted stage0.json replayed without an error")
		}
	})

	t.Run("advisory freeze removed", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		// The recorded advisory file still exists; make stage0.json claim a
		// different advisory hash — recomposition must diverge.
		var doc map[string]any
		if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "stage0.json")), &doc); err != nil {
			t.Fatal(err)
		}
		adv, ok := doc["advisory"].(map[string]any)
		if !ok {
			t.Fatalf("stage0.json lacks advisory block: %s", mustRead(t, filepath.Join(dir, "stage0.json")))
		}
		adv["sha256"] = strings.Repeat("cd", 32)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "stage0.json"), string(out))
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("drifted advisory hash replayed without an error")
		}
	})

	t.Run("fact gate tampered", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		var doc map[string]any
		if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "fact-gate.json")), &doc); err != nil {
			t.Fatal(err)
		}
		doc["validation"].(map[string]any)["status"] = "PARTIAL"
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "fact-gate.json"), string(out))
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("tampered fact-gate.json replayed without an error")
		}
	})

	t.Run("decision without stage0 provenance", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		if err := os.Remove(filepath.Join(dir, "stage0.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("decision.json without stage0.json replayed without an error")
		}
	})
}

// rewriteDecision applies mutate to the recorded decision.json and
// re-renders decision.md from the mutated package, so replay fails on the
// package comparison rather than on Markdown byte drift.
func rewriteDecision(t *testing.T, dir string, mutate func(*DecisionPackage)) {
	t.Helper()
	pkg, err := ValidateDecisionPackageJSON(mustRead(t, filepath.Join(dir, "decision.json")))
	if err != nil {
		t.Fatalf("recorded decision.json: %v", err)
	}
	mutate(&pkg)
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "decision.json"), string(data))
	writeFile(t, filepath.Join(dir, "decision.md"), string(RenderDecisionMarkdown(pkg)))
}

// TestReplayPreservesHumanJudgmentAndAction: replay re-derives the grounds
// of the recorded proposal but never re-runs the model and never rewrites
// the recorded judgment or proposed action — the historical model text is
// the record. A package whose stored judgment or action was rewritten after
// the run is rejected as drift instead of being silently accepted.
func TestReplayPreservesHumanJudgmentAndAction(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	var recorded DecisionPackage
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.runDir, "decision.json")), &recorded); err != nil {
		t.Fatal(err)
	}
	callsBefore := f.client.calls
	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if f.client.calls != callsBefore {
		t.Fatal("replay called the model to re-derive the judgment")
	}
	if rep.Decision == nil {
		t.Fatal("replay produced no decision package")
	}
	if !jsonEqual(rep.Decision.Judgment, recorded.Judgment) {
		t.Fatalf("replay rewrote the recorded judgment:\n got %+v\nwant %+v", rep.Decision.Judgment, recorded.Judgment)
	}
	if !jsonEqual(rep.Decision.ProposedAction, recorded.ProposedAction) {
		t.Fatalf("replay rewrote the recorded proposed action:\n got %+v\nwant %+v", rep.Decision.ProposedAction, recorded.ProposedAction)
	}
	if rep.Decision.ProposedAction.Instruction != recorded.ProposedAction.Instruction {
		t.Fatalf("historical instruction text changed: %q -> %q",
			recorded.ProposedAction.Instruction, rep.Decision.ProposedAction.Instruction)
	}
	// Support is recomputed from the same recorded grounds and reproduces
	// the recorded value; it is not replayed from the stored document.
	if !jsonEqual(rep.Decision.Support, recorded.Support) {
		t.Fatalf("recomputed support differs from the record:\n got %+v\nwant %+v", rep.Decision.Support, recorded.Support)
	}

	t.Run("rewritten judgment is rejected", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		rewriteDecision(t, dir, func(p *DecisionPackage) {
			p.Judgment.Summary = "rewritten conclusion after the run"
		})
		_, err := PrepareReplay(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), "judgment drift") {
			t.Fatalf("rewritten judgment was not reported as judgment drift: %v", err)
		}
	})
	t.Run("rewritten action is rejected", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		rewriteDecision(t, dir, func(p *DecisionPackage) {
			p.ProposedAction.Instruction = "close the ticket without verifying the build"
		})
		_, err := PrepareReplay(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), "proposed action drift") {
			t.Fatalf("rewritten action was not reported as proposed action drift: %v", err)
		}
	})
}

// TestReplayPreservesHumanDecisionHistory: replay carries the append-only
// Accept/Reject records as history, byte for byte. It re-verifies their
// binding to the source package but never creates a new decision, invents a
// timestamp or lets the latest record rewrite the delivered proposal.
func TestReplayPreservesHumanDecisionHistory(t *testing.T) {
	f, pkg := humanDecisionFixture(t)
	accept, acceptPath := recordHumanDecision(t, f.runDir, replayClockA, HumanDecisionAccept, "alice", "accept the delivered proposal")
	reject, rejectPath := recordHumanDecision(t, f.runDir, replayClockB, HumanDecisionReject, "bob", "deployment evidence is still missing")
	sourceBytes := map[string][]byte{
		accept.ID: mustRead(t, acceptPath),
		reject.ID: mustRead(t, rejectPath),
	}
	before := hashTree(t, f.runDir)

	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if len(rep.HumanDecisions) != 2 {
		t.Fatalf("replay review history = %d records, want 2", len(rep.HumanDecisions))
	}
	if rep.HumanDecisions[0].ID != accept.ID || rep.HumanDecisions[1].ID != reject.ID {
		t.Fatalf("replay review history order = %s, %s", rep.HumanDecisions[0].ID, rep.HumanDecisions[1].ID)
	}
	if len(rep.HumanDecisionHashes) != 2 {
		t.Fatalf("replay report review hashes = %d, want 2", len(rep.HumanDecisionHashes))
	}
	for i, id := range []string{accept.ID, reject.ID} {
		if got, want := rep.HumanDecisionHashes[i], hashBytes(sourceBytes[id]); got != want {
			t.Fatalf("replay report review hash[%d] = %q, want source hash %q", i, got, want)
		}
	}

	// A later replay clock proves the copied records keep their original
	// recorded_at values instead of being re-stamped.
	replayLater := func() time.Time { return replayClockB().Add(24 * time.Hour) }
	art, err := (ArtifactWriter{Clock: replayLater}).WriteReplay(context.Background(), t.TempDir(), rep)
	if err != nil {
		t.Fatalf("WriteReplay: %v", err)
	}
	for id, want := range sourceBytes {
		got := mustRead(t, filepath.Join(humanDecisionRecordDir(art.RootDir), id+".json"))
		if !bytes.Equal(got, want) {
			t.Fatalf("replayed record %s is not the original bytes:\n got %s\nwant %s", id, got, want)
		}
	}
	entries, err := os.ReadDir(humanDecisionRecordDir(art.RootDir))
	if err != nil {
		t.Fatalf("replay review directory: %v", err)
	}
	if len(entries) != len(sourceBytes) {
		t.Fatalf("replay created %d review records, want the %d history records", len(entries), len(sourceBytes))
	}
	var doc ReplayDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(art.RootDir, "replay.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.HumanDecisions) != 2 {
		t.Fatalf("replay.json review history = %d records, want 2", len(doc.HumanDecisions))
	}
	if len(doc.HumanDecisionHashes) != 2 {
		t.Fatalf("replay.json review hashes = %d, want 2", len(doc.HumanDecisionHashes))
	}
	for i, id := range []string{accept.ID, reject.ID} {
		if got, want := doc.HumanDecisionHashes[i], hashBytes(sourceBytes[id]); got != want {
			t.Fatalf("replay.json review hash[%d] = %q, want source hash %q", i, got, want)
		}
	}

	// The source run is never modified, and replay adds no review record to
	// a run that already has history.
	after := hashTree(t, f.runDir)
	for name, sum := range before {
		if after[name] != sum {
			t.Fatalf("source run file %s changed during replay", name)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("source run file count changed: %d -> %d", len(before), len(after))
	}
	if history, rerr := ReadHumanDecisions(f.runDir, pkg); rerr != nil || len(history) != 2 {
		t.Fatalf("source review history after replay = %+v, err=%v", history, rerr)
	}

	t.Run("reading a replay output leaves it unchanged", func(t *testing.T) {
		before := hashTree(t, art.RootDir)
		history, herr := ReadHumanDecisions(art.RootDir, pkg)
		if herr != nil {
			t.Fatalf("ReadHumanDecisions on the replay output: %v", herr)
		}
		if len(history) != 2 {
			t.Fatalf("replay output history = %d records, want 2", len(history))
		}
		after := hashTree(t, art.RootDir)
		for name, sum := range before {
			if after[name] != sum {
				t.Fatalf("reading the replay output modified %s", name)
			}
		}
		if len(after) != len(before) {
			t.Fatalf("reading the replay output changed its file count: %d -> %d", len(before), len(after))
		}
	})

	t.Run("absent history is valid", func(t *testing.T) {
		g := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
		grepp, gerr := PrepareReplay(context.Background(), g.runDir)
		if gerr != nil {
			t.Fatalf("PrepareReplay: %v", gerr)
		}
		if len(grepp.HumanDecisions) != 0 {
			t.Fatalf("run without review records gained history: %+v", grepp.HumanDecisions)
		}
		gart, werr := (ArtifactWriter{Clock: replayClockB}).WriteReplay(context.Background(), t.TempDir(), grepp)
		if werr != nil {
			t.Fatalf("WriteReplay: %v", werr)
		}
		if _, serr := os.Stat(humanDecisionRecordDir(gart.RootDir)); !os.IsNotExist(serr) {
			t.Fatalf("replay invented a review directory for a run without records: %v", serr)
		}
	})

	t.Run("tampered history rejected", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		var rec HumanDecisionRecord
		if err := json.Unmarshal(mustRead(t, filepath.Join(humanDecisionRecordDir(dir), accept.ID+".json")), &rec); err != nil {
			t.Fatal(err)
		}
		rec.Actor = "mallory"
		raw, merr := json.MarshalIndent(rec, "", "  ")
		if merr != nil {
			t.Fatal(merr)
		}
		writeFile(t, filepath.Join(humanDecisionRecordDir(dir), accept.ID+".json"), string(raw))
		if _, rerr := PrepareReplay(context.Background(), dir); rerr == nil {
			t.Fatal("replay accepted a tampered human decision record")
		}
	})
}

// TestReplaySupportDriftRejected: replay reruns support (and the machine
// admissibility rules) from the recorded grounds. A stored package whose
// support or machine disposition no longer matches the recomputation is a
// technical error naming that axis — the recorded value is never accepted
// in place of the new one.
func TestReplaySupportDriftRejected(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)

	t.Run("support drift", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		rewriteDecision(t, dir, func(p *DecisionPackage) {
			// Any other level is a valid package value; the point is that
			// replay re-derives support and refuses the stored difference.
			if p.Support.Level == SupportLevelSubstantiated {
				p.Support.Level = SupportLevelLimited
			} else {
				p.Support.Level = SupportLevelSubstantiated
			}
		})
		_, err := PrepareReplay(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), "support drift") {
			t.Fatalf("recorded support divergence was not reported as support drift: %v", err)
		}
	})

	t.Run("machine admissibility drift", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		rewriteDecision(t, dir, func(p *DecisionPackage) {
			if p.MachineDisposition.Automation == AutomationAllow {
				p.MachineDisposition.Automation = AutomationWarn
			} else {
				p.MachineDisposition.Automation = AutomationAllow
			}
		})
		_, err := PrepareReplay(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), "machine admissibility drift") {
			t.Fatalf("recorded machine divergence was not reported as machine drift: %v", err)
		}
	})
}

// TestReplayDecisionAbsentIsLegacy: a run recorded before decision artifacts
// existed still replays — absent decision files stay absent.
func TestReplayDecisionAbsentIsLegacy(t *testing.T) {
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)
	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if rep.Decision != nil {
		t.Fatal("legacy run gained a decision package")
	}
	art, err := (ArtifactWriter{Clock: replayClockB}).WriteReplay(context.Background(), t.TempDir(), rep)
	if err != nil {
		t.Fatalf("WriteReplay: %v", err)
	}
	if _, err := os.Stat(filepath.Join(art.RootDir, "decision.json")); !os.IsNotExist(err) {
		t.Fatal("replay invented decision.json for a run that never had one")
	}
	var doc ReplayDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(art.RootDir, "replay.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.DecisionHash != "" {
		t.Fatalf("legacy replay recorded a decision hash: %+v", doc)
	}
}

// netGuard returns a counting no-network sentinel: it installs a
// RoundTripper as http.DefaultTransport that fails every request, so any
// HTTP dial a replay path attempts both counts and errors. Replay paths
// take no providers at all, so the only way a dial could happen is a
// regression that reaches for OSV/tracker/registry — the counter proves
// none does.
func netGuard(t *testing.T) *int64 {
	t.Helper()
	count := new(int64)
	prev := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt64(count, 1)
		return nil, errors.New("agenttriage test: network access forbidden during offline replay")
	})
	t.Cleanup(func() { http.DefaultTransport = prev })
	return count
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestOfflineReplayStage0Reproduces: ReplayStage0 rebuilds the recorded
// Stage 0 projection from artifacts alone — no snapshot re-materialization,
// no advisory lane, no git access — even after the source repository and
// the analysis artifacts are gone.
func TestOfflineReplayStage0Reproduces(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	guard := netGuard(t)

	// Stage 0 replay consumes only its own artifacts: the snapshot root may
	// be deleted and the analysis files are irrelevant.
	if err := os.RemoveAll(f.repoDir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"assessment.json", "assessment.md", "decision.json", "decision.md", "fact-gate.json", "raw-agent.json"} {
		if err := os.Remove(filepath.Join(f.runDir, name)); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}

	s0, err := ReplayStage0(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("ReplayStage0: %v", err)
	}
	if *guard != 0 {
		t.Fatalf("stage0 replay dialed a network provider %d time(s)", *guard)
	}
	var doc stage0Document
	if err := json.Unmarshal(mustRead(t, filepath.Join(f.runDir, "stage0.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if s0.ConfigHash != doc.ConfigHash || s0.CatalogEntry.ID != doc.CatalogEntry.ID {
		t.Fatalf("replayed stage0 identity differs: %+v", s0)
	}
	if s0.SelectedRef.Name != doc.SelectedRef.Name || s0.RefResolution.SelectedID != doc.RefResolution.SelectedID {
		t.Fatalf("replayed ref resolution differs: %+v", s0.RefResolution)
	}
	if s0.Advisory.SHA256 != doc.Advisory.SHA256 || s0.Advisory.Source != doc.Advisory.Source {
		t.Fatalf("replayed advisory freeze differs: %+v", s0.Advisory)
	}
	if s0.Raw.TicketHash == "" {
		t.Fatal("replayed stage0 lost the intake record")
	}
	if len(s0.Materials.Materials) == 0 {
		t.Fatal("replayed stage0 lost the material set")
	}
	if len(s0.Validation.Fields) == 0 {
		t.Fatal("replayed stage0 lost the intake validation")
	}
}

// TestOfflineReplayStage0RequiresArtifacts: every companion the recorded
// Stage 0 produced is mandatory — removing intake.json, the proposal, the
// material set or stage0.json itself is a technical error, and removing
// the frozen advisory document fails closed instead of re-resolving.
func TestOfflineReplayStage0RequiresArtifacts(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)

	for _, name := range []string{"stage0.json", "intake.json", "intake-proposal.json", "materials.json"} {
		t.Run("missing "+name, func(t *testing.T) {
			dir := copyRunDir(t, f.runDir)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if _, err := ReplayStage0(context.Background(), dir); err == nil {
				t.Fatalf("ReplayStage0 succeeded without %s", name)
			}
		})
	}

	t.Run("frozen advisory missing", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		var doc stage0Document
		if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "stage0.json")), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Advisory.Path == "" {
			t.Fatal("fixture records no advisory path")
		}
		if err := os.Remove(doc.Advisory.Path); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplayStage0(context.Background(), dir); err == nil {
			t.Fatal("ReplayStage0 succeeded with the frozen advisory removed")
		}
	})

	t.Run("frozen advisory corrupt", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		var doc stage0Document
		if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "stage0.json")), &doc); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(doc.Advisory.Path, []byte(`{"id":"CVE-0000-0000","replaced":true}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplayStage0(context.Background(), dir); err == nil {
			t.Fatal("ReplayStage0 accepted a corrupted frozen advisory")
		}
	})
}

// TestOfflineReplayStage0PreparePath: the full replay verifies the same
// Stage 0 provenance — removing the frozen advisory document or the
// material set is a technical error inside PrepareReplay too, not just
// the standalone verifier.
func TestOfflineReplayStage0PreparePath(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)

	t.Run("advisory missing", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		var doc stage0Document
		if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "stage0.json")), &doc); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(doc.Advisory.Path); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("PrepareReplay succeeded without the frozen advisory")
		}
	})
	t.Run("materials missing", func(t *testing.T) {
		dir := copyRunDir(t, f.runDir)
		if err := os.Remove(filepath.Join(dir, "materials.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareReplay(context.Background(), dir); err == nil {
			t.Fatal("PrepareReplay succeeded without materials.json")
		}
	})
}

// TestOfflineReplayNoLiveSource: replay never touches the repository the
// manifest names — the recorded run replays identically after the entire
// source tree is deleted. Any git resolve, content re-hash or artifact
// read would surface here as an error.
func TestOfflineReplayNoLiveSource(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	guard := netGuard(t)

	if err := os.RemoveAll(f.repoDir); err != nil {
		t.Fatal(err)
	}
	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay with the source tree deleted: %v", err)
	}
	if rep.Decision == nil || canonicalDecisionHash(*rep.Decision) != canonicalDecisionHash(*rep.SourceDecision) {
		t.Fatal("replay without the live source did not reproduce the recorded decision")
	}
	if got, want := canonicalAssessmentHash(rep.Assessment), canonicalAssessmentHash(f.stored); got != want {
		t.Fatalf("offline replay assessment hash %s != recorded %s", got, want)
	}
	if *guard != 0 {
		t.Fatalf("replay dialed a network provider %d time(s)", *guard)
	}
	if f.client.calls != 1 {
		t.Fatalf("replay re-invoked the chat client: calls=%d", f.client.calls)
	}
}

// TestOfflineReplayNoRemoteAccess: the end-to-end decision replay never
// dials a provider — a dead-network environment changes nothing.
func TestOfflineReplayNoRemoteAccess(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	guard := netGuard(t)
	callsBefore := f.client.calls

	if _, err := PrepareReplay(context.Background(), f.runDir); err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if *guard != 0 {
		t.Fatalf("replay dialed a network provider %d time(s)", *guard)
	}
	if f.client.calls != callsBefore {
		t.Fatal("replay invoked the chat client")
	}
}

func replayEmptyProofReport(t *testing.T, dir string) FalsifierReport {
	t.Helper()
	r := FalsifierReport{SchemaVersion: FalsifierVerificationSchemaVersion, RuleSetHash: ""}
	r.Hash = reportHash(r)
	if err := (ArtifactWriter{}).WriteFalsifierReport(context.Background(), dir, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReplayRecomputesFalsifier(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	r := replayEmptyProofReport(t, f.runDir)
	before, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if before.Decision == nil {
		t.Fatal("replay did not recompute decision")
	}
	if reportHash(r) != r.Hash {
		t.Fatal("fixture report was not canonical")
	}
	archive, err := ReadObservationArchive(filepath.Join(f.runDir, "observation-archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Observations) < 0 {
		t.Fatal("unreachable")
	}
	after, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("replay after archive recomposition: %v", err)
	}
	if after.Decision == nil || canonicalDecisionHash(*after.Decision) != canonicalDecisionHash(*before.Decision) {
		t.Fatal("irrelevant archive input changed decision hash")
	}
}

func TestReplayDoesNotTrustPersistedVerified(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	r := FalsifierReport{SchemaVersion: FalsifierVerificationSchemaVersion, RuleSetHash: "rules", Proofs: []FalsifierProof{{ID: "fp", ProposalID: "fp", ClaimID: "missing", ConditionID: "cond", Kind: FalsifierCodeAbsent, Status: FalsifierVerified, Basis: BasisCheckerVerified}}}
	r.Hash = reportHash(r)
	if err := (ArtifactWriter{}).WriteFalsifierReport(context.Background(), f.runDir, r); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
		t.Fatal("persisted VERIFIED proof was accepted without recomputation")
	}
}

func TestReplayFalsifierObservationTamper(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	replayEmptyProofReport(t, f.runDir)
	p := filepath.Join(f.runDir, "observation-archive.json")
	a, err := ReadObservationArchive(p)
	if err != nil {
		t.Fatal(err)
	}
	a.Observations = append(a.Observations, RecordedObservation{ID: "tampered", Payload: json.RawMessage(`{"bad":true}`), DataSHA256: strings.Repeat("0", 64)})
	if err := WriteObservationArchive(context.Background(), p, observationSliceStore{items: a.Observations}); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
		t.Fatal("observation payload tamper was accepted")
	}
}

func TestReplayFalsifierHashMismatch(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	r := replayEmptyProofReport(t, f.runDir)
	r.Hash = strings.Repeat("f", 64)
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(f.runDir, "falsifier-verification.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
		t.Fatal("invalid falsifier hash was accepted")
	}
}

func TestReplayFalsifierDemotion(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	replayEmptyProofReport(t, f.runDir)
	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if rep.Assessment.Verdict != f.stored.Verdict {
		t.Fatalf("replay verdict=%s want %s", rep.Assessment.Verdict, f.stored.Verdict)
	}
	if rep.Decision == nil || !rep.Decision.MachineDisposition.Automation.Valid() {
		t.Fatalf("replayed package lost its machine automation outcome: %+v", rep.Decision)
	}
}

func TestReplayFalsifierNoNetworkOrLLM(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	replayEmptyProofReport(t, f.runDir)
	guard := netGuard(t)
	calls := f.client.calls
	if _, err := PrepareReplay(context.Background(), f.runDir); err != nil {
		t.Fatalf("PrepareReplay: %v", err)
	}
	if *guard != 0 {
		t.Fatalf("replay made network calls: %d", *guard)
	}
	if f.client.calls != calls {
		t.Fatalf("replay made LLM calls: %d -> %d", calls, f.client.calls)
	}
}

func TestReplayFalsifierCrossRunRejected(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA)
	r := replayEmptyProofReport(t, f.runDir)
	r.Proofs = []FalsifierProof{{ID: "fp", ProposalID: "fp", ClaimID: "missing", ConditionID: "cond", Kind: FalsifierCodeAbsent, Status: FalsifierVerified, Basis: BasisCheckerVerified}}
	r.Hash = reportHash(r)
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(f.runDir, "falsifier-verification.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := ReadObservationArchive(filepath.Join(f.runDir, "observation-archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.Observations = append(a.Observations, RecordedObservation{ID: "foreign", RunID: "foreign-run", Attempt: 2, Payload: json.RawMessage(`{"x":1}`), DataSHA256: sha256Hex(t, []byte(`{"x":1}`))})
	if err := WriteObservationArchive(context.Background(), filepath.Join(f.runDir, "observation-archive.json"), observationSliceStore{items: a.Observations}); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(context.Background(), f.runDir); err == nil {
		t.Fatal("cross-run proof evidence was accepted")
	}
}

// TestReplayUsesRecordedReachClassification: replay rebuilds the observation
// index from the recording run's audit events, never from today's registry. A
// saved pin that says a call established reachability keeps that meaning even
// though the current capability registry declares no evidence class for the
// same tool — a registry change alters new-run pins, not saved-run
// definitions.
func TestReplayUsesRecordedReachClassification(t *testing.T) {
	spec, ok := evidencetools.DefaultCheckCatalog().Lookup("find_symbol")
	if !ok || spec.Evidence != evidencetools.EvidenceNone {
		t.Fatalf("fixture assumes find_symbol declares no evidence class: %+v", spec)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o755); err != nil {
		t.Fatal(err)
	}
	recorded := AuditEvent{
		Type: AuditEventToolCall, RunID: "run-recorded", Attempt: 1,
		Tool: "find_symbol", ObservationID: "det-0001", Status: string(ToolStatusOK),
		Coverage: "PARTIAL", DataSHA256: strings.Repeat("a", 64), ReachEvidence: true,
	}
	line, err := json.Marshal(recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit", "events.jsonl"), append(line, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	pin, ok := observationIndexFromAudit(dir, "run-recorded", 1)["det-0001"]
	if !ok {
		t.Fatal("recorded tool_call event did not produce an observation pin")
	}
	if !pin.ReachEvidence {
		t.Fatal("recorded reachability classification was re-derived from today's registry")
	}
	if pin.DataSHA256 != recorded.DataSHA256 || pin.Coverage != recorded.Coverage || pin.Tool != recorded.Tool {
		t.Fatalf("recorded pins were not preserved: %+v", pin)
	}
}

// TestReplayHonoursAttemptRunIdentity pins the identity split replay must
// respect: archived observations carry the attempt-qualified run id the live
// tools stamped, while audit tool-call events carry the agent run id. Using
// one for the other makes every observation read as foreign evidence.
func TestReplayHonoursAttemptRunIdentity(t *testing.T) {
	store := NewRunObservationStore(AttemptRunID("finding-1", 1), 1)
	recordObservation(store, ToolObservation{ID: "det-1", Tool: "verify_code_absence", Status: ToolStatusOK})
	obs := store.Observations()
	if len(obs) != 1 {
		t.Fatalf("observations = %d", len(obs))
	}
	if obs[0].RunID != AttemptRunID("finding-1", 1) {
		t.Fatalf("archive run id = %q", obs[0].RunID)
	}
	// The verifier accepts exactly that identity and rejects the agent run id.
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.RunID = obs[0].RunID
	in.Observations = []RecordedObservation{*o}
	in.RunID = obs[0].RunID
	if got := runProof(t, in, s); got.Status != FalsifierVerified {
		t.Fatalf("attempt-qualified archive rejected: %+v", got)
	}
	agentRunID := "finding-1@20260101T000000.000000000Z-deadbeef"
	if r := verifyWithRunID(t, in, s, agentRunID); r.Status == FalsifierVerified {
		t.Fatalf("agent run id admitted: %+v", r)
	}
}

func verifyWithRunID(t *testing.T, in FalsifierVerificationInput, s MandatoryConditionSource, runID string) FalsifierProof {
	t.Helper()
	in.RunID = runID
	return NewFalsifierVerifier(s).Verify(context.Background(), in).Proofs[0]
}

// TestReplayRecordedValidationIgnoresUnreferencedEvidence pins the coverage
// contract replay must reproduce: the live gate validates the evidence claims
// cite, so an evidence entry no claim references never turns a recorded
// COMPLETE into drift.
func TestReplayRecordedValidationIgnoresUnreferencedEvidence(t *testing.T) {
	fv := completeValidation()
	a := goodAssessment()
	a.Evidence = append(a.Evidence,
		EvidenceRef{ID: "unused-1", Kind: "file", Locator: "main.go"},
		EvidenceRef{ID: "unused-2", Kind: "file", Locator: "main.go"},
	)
	gate := FactGate{Offline: true, Recorded: &fv}
	got := gate.Validate(context.Background(), goodStage0().Input, goodStage0().Snapshot, a)
	if got.Status == ValidationFailed {
		t.Fatalf("unreferenced evidence failed the replay gate: %+v", got.Limitations)
	}

	// A referenced-but-uncovered evidence entry is still drift.
	a.Claims[0].EvidenceRefs = append(a.Claims[0].EvidenceRefs, "unused-1")
	if got := gate.Validate(context.Background(), goodStage0().Input, goodStage0().Snapshot, a); got.Status != ValidationFailed {
		t.Fatalf("uncovered referenced evidence accepted: %+v", got)
	}
}

// customSurfaceTools is a tool executor whose advertised surface differs
// from the current ReadOnlyTools definitions: replay must use the persisted
// prompt-input.v1 surface, not rebuild today's registry.
type customSurfaceTools struct{}

func (customSurfaceTools) Definitions() []llm.ToolDefinition {
	return []llm.ToolDefinition{{Type: "function", Function: llm.FunctionSpec{
		Name: "custom_surface_read", Description: "recorded-only surface", Parameters: json.RawMessage(`{"type":"object"}`),
	}}}
}

func (customSurfaceTools) Call(context.Context, string, json.RawMessage) ToolObservation {
	return ToolObservation{ID: "o1", Tool: "custom_surface_read", Status: ToolStatusOK}
}

type failingTransport struct{ calls *atomic.Int64 }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, errors.New("network disabled by replay test")
}

// TestReplayUsesCapturedPromptAndMaterials records a run over a supplied
// captured advisory/fix set with a non-standard tool surface, deletes the
// original material files and the repository, disables the network, and
// replays from the saved prompt-input.v1 plus the digest-addressed archive.
func TestReplayUsesCapturedPromptAndMaterials(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "main.go"), "package main\n\nfunc main() {}\n")
	inputJSON, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     "captured-prompt-1",
		Vulnerability: Vulnerability{IDs: []string{"CVE-2026-0100"}},
		Target:        Target{Repository: repo},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ParseFindings(strings.NewReader(string(inputJSON)))
	if err != nil {
		t.Fatal(err)
	}
	in := findings[0]
	manifest, err := LocalSnapshotBuilder{}.Build(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	manifestDir := t.TempDir()
	recordRaw := []byte(`{"id":"CVE-2026-0100","summary":"captured advisory probe"}`)
	fixRaw := []byte("--- a/probe.go\n+++ b/probe.go\n+fix\n")
	_, recordSHA := investigationFile(t, manifestDir, "advisory.json", recordRaw)
	_, fixSHA := investigationFile(t, manifestDir, "fix.diff", fixRaw)
	inv := InvestigationInputs{
		Records: []CapturedRecord{{RecordID: "CVE-2026-0100", SHA256: recordSHA, Size: int64(len(recordRaw)), Source: "operator-freeze", Raw: recordRaw}},
		Fixes: []CapturedFix{{RecordID: "CVE-2026-0100", RecordSHA256: recordSHA, Locator: "https://example.test/fix/probe.diff",
			Outcome: CapturedFixCaptured, SHA256: fixSHA, Size: int64(len(fixRaw)), Raw: fixRaw}},
	}
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	agent := Assessment{
		SchemaVersion:  AssessmentSchemaVersion,
		FindingID:      in.Finding.FindingID,
		Verdict:        VerdictInconclusive,
		Summary:        "captured material needs deployment facts",
		Claims:         []Claim{{ID: "c1", Statement: "the captured advisory does not establish exploitability", Basis: PremiseInterpreted, Subject: "exploitability", Scope: "captured record scope", DecisionRelevant: true}},
		ProposedAction: HumanAction{Kind: HumanActionObtainEvidence, Instruction: "capture deployment facts", Rationale: "reachability is unproven", Scope: "deployment", DecisiveClaimIDs: []string{"c1"}, ReconsiderWhen: []string{"deployment facts are captured"}},
	}
	agentJSON, err := json.Marshal(agent)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	w := ArtifactWriter{Model: "replay-captured", ToolVersions: map[string]string{"izyan": "test"}}
	runDir, err := ReserveRunDir(outDir, in.Finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	w.RunDir = runDir
	if err := w.WriteInvestigationInputs(ctx, runDir, inv); err != nil {
		t.Fatalf("captured archive: %v", err)
	}
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: string(agentJSON)}}}
	tools := customSurfaceTools{}
	run, err := AgentRunner{
		Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 2},
		Materials: BuildAgentMaterials(MaterialSet{}, inv),
	}.Run(ctx, in, manifest)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := w.Write(ctx, outDir, in, manifest, run, run.Assessment, nil, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, PromptInputArtifactName)); err != nil {
		t.Fatalf("prompt-input.v1 was not persisted before/with the run: %v", err)
	}

	// Replay must need neither the manifest files nor the repository.
	if err := os.RemoveAll(manifestDir); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repo); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	oldTransport := http.DefaultTransport
	http.DefaultTransport = failingTransport{calls: &calls}
	defer func() { http.DefaultTransport = oldTransport }()

	rep, err := PrepareReplay(ctx, runDir)
	if err != nil {
		t.Fatalf("replay from captured prompt/materials: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("replay made %d network request(s)", calls.Load())
	}
	if rep.PromptInput == nil {
		t.Fatal("replay did not verify persisted prompt-input.v1")
	}
	if rep.PromptInput.PromptHash != run.PromptHash {
		t.Fatalf("replay prompt hash %s != recorded %s", rep.PromptInput.PromptHash, run.PromptHash)
	}
	if len(rep.PromptInput.Tools) != 1 || rep.PromptInput.Tools[0].Function.Name != "custom_surface_read" {
		t.Fatalf("replay used a rebuilt tool surface: %+v", rep.PromptInput.Tools)
	}
	if rep.Investigation == nil || len(rep.Investigation.Records) != 1 || len(rep.Investigation.Fixes) != 1 {
		t.Fatalf("replay did not verify the captured material archive: %+v", rep.Investigation)
	}
	for _, lim := range rep.Limitations {
		if strings.Contains(lim, "history-only run") {
			t.Fatalf("replay treated a prompt-input-bearing run as history-only: %v", rep.Limitations)
		}
	}
}

// TestReplayPreservesProductTarget: the product build a run identified is
// persisted with its material projection, re-derived and verified at replay,
// carried into the replay report, and tampering with the recorded target is
// drift rather than a silently different build.
func TestReplayPreservesProductTarget(t *testing.T) {
	ctx := context.Background()
	f := recordReplayRun(t, newReplayRepo(t), t.TempDir(), "test-model", replayClockA, replayClockA)

	target := domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		BuildTags: []string{"netgo"}, CGOEnabled: true,
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	recorded := []byte(`{"schema_version":"investigation-inputs.v1","build":` + string(targetJSON) + `,"build_target":` + string(targetJSON) + `}`)
	if err := os.WriteFile(filepath.Join(f.runDir, InvestigationInputsArtifactName), recorded, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := PrepareReplay(ctx, f.runDir)
	if err != nil {
		t.Fatalf("PrepareReplay with a recorded product target: %v", err)
	}
	art, err := (ArtifactWriter{Clock: replayClockB}).WriteReplay(ctx, t.TempDir(), rep)
	if err != nil {
		t.Fatalf("WriteReplay: %v", err)
	}
	var replayDoc map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, filepath.Join(art.RootDir, "replay.json")), &replayDoc); err != nil {
		t.Fatal(err)
	}
	raw, ok := replayDoc["build_target"]
	if !ok {
		t.Fatal("replay.json does not describe the identified product build")
	}
	var replayed domain.ProductTarget
	if err := json.Unmarshal(raw, &replayed); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(replayed, target) {
		t.Fatalf("replay product target = %+v, want %+v", replayed, target)
	}
	var copied map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, filepath.Join(art.RootDir, InvestigationInputsArtifactName)), &copied); err != nil {
		t.Fatal(err)
	}
	if _, ok := copied["build_target"]; !ok {
		t.Fatal("replay output lost the recorded product build from its material projection")
	}

	// A changed target that no recorded input supports is drift.
	damaged := copyRunDir(t, f.runDir)
	tampered := target
	tampered.GOARCH = "arm64"
	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedProjection := []byte(`{"schema_version":"investigation-inputs.v1","build":` + string(targetJSON) + `,"build_target":` + string(tamperedJSON) + `}`)
	if err := os.WriteFile(filepath.Join(damaged, InvestigationInputsArtifactName), tamperedProjection, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplay(ctx, damaged); err == nil || !strings.Contains(err.Error(), "build target") {
		t.Fatalf("replay accepted a tampered product target: %v", err)
	}
}

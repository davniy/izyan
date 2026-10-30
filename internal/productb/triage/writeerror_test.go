package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/fedorovmv/izyan/internal/llm"
)

// decodeRunDirName inverts the percent-encoding of RunDirName for tests:
// it proves the name→ID mapping is injective rather than trusting it.
func decodeRunDirName(t *testing.T, name string) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] != '%' {
			b.WriteByte(name[i])
			continue
		}
		v, err := strconv.ParseUint(name[i+1:i+3], 16, 8)
		if err != nil {
			t.Fatalf("undecodable run dir name %q", name)
		}
		b.WriteByte(byte(v))
		i += 2
	}
	return b.String()
}

// TestRunDirNameCollisionFree proves distinct finding IDs never alias onto
// one directory name — the mapping is injective, including IDs crafted to
// look like an already-encoded name (a literal "%2f" must not collide
// with an escaped '/').
func TestRunDirNameCollisionFree(t *testing.T) {
	names := map[string]string{}
	ids := []string{
		"scanner/123", "scanner_123", "scanner\\123", "scanner 123",
		"scanner:123", "SCANNER_123", "a/b", "a//b", "a_b",
		"scanner%2f123", "scanner%2F123", "%2f", "%252f",
		"ticket/SEC-42", "ticket%2fSEC-42", "пробел",
	}
	for _, id := range ids {
		name, err := RunDirName(id)
		if err != nil {
			t.Fatalf("RunDirName(%q): %v", id, err)
		}
		if prev, dup := names[name]; dup {
			t.Fatalf("RunDirName(%q) == RunDirName(%q) == %q: finding IDs collide", id, prev, name)
		}
		names[name] = id
		if got := decodeRunDirName(t, name); got != id {
			t.Fatalf("RunDirName(%q) = %q decodes to %q, not injective", id, name, got)
		}
	}
	// The delta-review case: an ID equal to a previously suffixed name maps
	// to itself, never onto the other finding's directory.
	suffixed, err := RunDirName("scanner_123-328e5774")
	if err != nil || suffixed != "scanner_123-328e5774" {
		t.Fatalf("clean suffixed-looking ID: %q, err=%v", suffixed, err)
	}
	// Clean IDs keep the unsuffixed, human-readable contract.
	if n, _ := RunDirName("scanner_123"); n != "scanner_123" {
		t.Fatalf("clean finding ID got encoded name %q", n)
	}
	if n, _ := RunDirName("scanner/123"); n != "scanner%2f123" {
		t.Fatalf("dirty finding ID must be percent-encoded, got %q", n)
	}
}

// TestWriteErrorDocument checks the error.json contract: schema, identity,
// verbatim error text and a stamp — written through the same naming
// contract as Write.
func TestWriteErrorDocument(t *testing.T) {
	out := t.TempDir()
	in := inputForID(t, "scanner/123")
	w := ArtifactWriter{Clock: artifactClock()}

	path, err := w.WriteError(context.Background(), out, in, errors.New("repo unreachable"))
	if err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	name, _ := RunDirName("scanner/123")
	if path != filepath.Join(out, name, errorFileName) {
		t.Fatalf("WriteError path %q not under RunDirName %q", path, name)
	}
	var doc ErrorDocument
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != ErrorSchemaVersion || doc.FindingID != "scanner/123" ||
		doc.Error != "repo unreachable" || doc.Time == "" {
		t.Fatalf("error.json: %+v", doc)
	}
}

// TestClaimRunDirErrorMarker pins the shared ownership contract: a run
// directory claimed by error.json of finding A refuses artifacts of finding
// B, and a directory claimed by input.json refuses error.json of finding B.
func TestClaimRunDirErrorMarker(t *testing.T) {
	out := t.TempDir()
	w := ArtifactWriter{Clock: artifactClock()}

	dir := filepath.Join(out, "shared")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	errDoc, _ := json.Marshal(ErrorDocument{
		SchemaVersion: ErrorSchemaVersion, FindingID: "owner-a", Error: "x"})
	if err := os.WriteFile(filepath.Join(dir, errorFileName), errDoc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := claimRunDir(dir, "owner-a"); err != nil {
		t.Fatalf("owner re-claim rejected: %v", err)
	}
	if err := claimRunDir(dir, "other-finding"); err == nil {
		t.Fatal("foreign finding claimed a directory owned via error.json")
	}
	if _, err := w.WriteError(context.Background(), out, inputForID(t, "other"), errors.New("x")); err != nil {
		t.Fatalf("WriteError for distinct finding: %v", err)
	}

	// input.json marker equally blocks foreign error.json writes.
	dir2 := filepath.Join(out, "claimed-by-input")
	if err := os.MkdirAll(dir2, 0o755); err != nil {
		t.Fatal(err)
	}
	inputDoc, _ := json.Marshal(Finding{SchemaVersion: FindingSchemaVersion, FindingID: "owner-b"})
	if err := os.WriteFile(filepath.Join(dir2, "input.json"), inputDoc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := claimRunDir(dir2, "owner-b"); err != nil {
		t.Fatalf("owner re-claim rejected: %v", err)
	}
	if err := claimRunDir(dir2, "other-finding"); err == nil {
		t.Fatal("foreign finding claimed a directory owned via input.json")
	}
}

// TestWriteErrorThenWriteSameFinding mirrors the retry flow: a failed run
// leaves error.json, a later successful run of the SAME finding may reuse
// the directory and add its artifacts alongside.
func TestWriteErrorThenWriteSameFinding(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}

	if _, err := w.WriteError(context.Background(), out, in, errors.New("agent timeout")); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	art, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write after error.json of the same finding: %v", err)
	}
	for _, p := range []string{art.AssessmentPath, filepath.Join(art.RootDir, errorFileName)} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s: %v", p, err)
		}
	}
}

// TestWriteFailurePartialArtifacts: an agent run that died mid-conversation
// still leaves error.json, a raw-agent.json marked partial:true with the
// failure class and verbatim transcript, and the audit events accumulated
// before the failure — the run is diagnosable, not just recorded.
func TestWriteFailurePartialArtifacts(t *testing.T) {
	out := t.TempDir()
	in := inputForID(t, "scanner-123")
	w := ArtifactWriter{Clock: artifactClock()}
	run := AgentRun{
		RawMessages: []llm.ChatMessage{
			{Role: "user", Content: "finding data"},
			{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: "c1", Type: "function", Function: llm.FunctionCall{Name: "read_file"}}}},
		},
		PromptHash: "ph",
		Steps:      2,
		ToolCalls:  1,
		ErrorClass: ErrClassProvider,
	}
	events := []AuditEvent{{Type: AuditEventRunStarted, Status: "error"}}
	runErr := errors.New("agenttriage: chat: llm status 500: boom")

	path, err := w.WriteFailure(context.Background(), out, in, run, runErr, events)
	if err != nil {
		t.Fatalf("WriteFailure: %v", err)
	}
	name, _ := RunDirName("scanner-123")
	dir := filepath.Join(out, name)
	if path != filepath.Join(dir, errorFileName) {
		t.Fatalf("WriteFailure path %q not under %q", path, dir)
	}

	var errDoc ErrorDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, errorFileName)), &errDoc); err != nil {
		t.Fatal(err)
	}
	if errDoc.Error != runErr.Error() || errDoc.FindingID != "scanner-123" {
		t.Fatalf("error.json: %+v", errDoc)
	}

	var rawDoc RawAgentDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, "raw-agent.json")), &rawDoc); err != nil {
		t.Fatal(err)
	}
	if !rawDoc.Partial || rawDoc.Error != runErr.Error() || rawDoc.ErrorClass != ErrClassProvider {
		t.Fatalf("raw-agent.json partial fields: %+v", rawDoc)
	}
	if len(rawDoc.Messages) != 2 || rawDoc.Steps != 2 || rawDoc.ToolCalls != 1 || rawDoc.PromptHash != "ph" {
		t.Fatalf("raw-agent.json lost run state: %+v", rawDoc)
	}

	auditBytes := mustRead(t, filepath.Join(dir, "audit", "events.jsonl"))
	var ev AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(auditBytes))), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != AuditEventRunStarted || ev.Status != "error" || ev.RunID == "" {
		t.Fatalf("audit event: %+v", ev)
	}
}

// TestWriteFailureNoRunState: a run that failed before the first prompt
// still records the mandatory partial transcript and audit error channel.
func TestWriteFailureNoRunState(t *testing.T) {
	out := t.TempDir()
	in := inputForID(t, "scanner-123")
	w := ArtifactWriter{Clock: artifactClock()}

	if _, err := w.WriteFailure(context.Background(), out, in, AgentRun{}, errors.New("boom"), nil); err != nil {
		t.Fatalf("WriteFailure: %v", err)
	}
	name, _ := RunDirName("scanner-123")
	dir := filepath.Join(out, name)
	mustRead(t, filepath.Join(dir, errorFileName))
	var raw RawAgentDocument
	if data, err := os.ReadFile(filepath.Join(dir, "raw-agent.json")); err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if !raw.Partial || raw.Error != "boom" {
		t.Fatalf("raw-agent failure channel = %+v", raw)
	}
	data, err := os.ReadFile(filepath.Join(dir, "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"type":"error"`) {
		t.Fatalf("audit failure event missing: %s", data)
	}
}

// TestWriteFailureKeepsCompleteTranscript: a failure that lands after the
// canonical Write must never demote the completed raw-agent.json back to
// partial — error.json records the technical failure while the finished
// transcript survives untouched.
func TestWriteFailureKeepsCompleteTranscript(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}

	if _, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil); err != nil {
		t.Fatalf("Write: %v", err)
	}
	name, _ := RunDirName("scanner-123")
	dir := filepath.Join(out, name)
	before := mustRead(t, filepath.Join(dir, "raw-agent.json"))

	if _, err := w.WriteFailure(context.Background(), out, in, run, errors.New("decision: final gate check C12 is FAIL"), nil); err != nil {
		t.Fatalf("WriteFailure: %v", err)
	}
	after := mustRead(t, filepath.Join(dir, "raw-agent.json"))
	if string(before) != string(after) {
		t.Fatal("post-Write failure rewrote the completed raw-agent.json")
	}
	var doc RawAgentDocument
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Partial || doc.Error != "" {
		t.Fatalf("completed transcript was demoted: %+v", doc)
	}
	var errDoc ErrorDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(dir, errorFileName)), &errDoc); err != nil {
		t.Fatal(err)
	}
	if errDoc.Error == "" {
		t.Fatal("error.json must still record the post-agent failure")
	}
}

// TestWriteFailureEmptyRunKeepsPartial: an outer failure path that carries
// no run state must never replace the partial transcript an inner stage
// already persisted — the empty record adds nothing but noise.
func TestWriteFailureEmptyRunKeepsPartial(t *testing.T) {
	out := t.TempDir()
	in := inputForID(t, "scanner-123")
	w := ArtifactWriter{Clock: artifactClock()}
	run := AgentRun{
		RawMessages: []llm.ChatMessage{
			{Role: "user", Content: "finding data"},
			{Role: "assistant", Content: "unstructured noise"},
		},
		PromptHash: "ph",
		Steps:      3,
		ErrorClass: ErrClassStepBudget,
	}
	if _, err := w.WriteFailure(context.Background(), out, in, run, errors.New("agenttriage: step budget exceeded"), nil); err != nil {
		t.Fatalf("WriteFailure: %v", err)
	}
	name, _ := RunDirName("scanner-123")
	dir := filepath.Join(out, name)
	before := mustRead(t, filepath.Join(dir, "raw-agent.json"))

	if _, err := w.WriteFailure(context.Background(), out, in, AgentRun{}, errors.New("outer wrapper error"), nil); err != nil {
		t.Fatalf("WriteFailure(empty): %v", err)
	}
	after := mustRead(t, filepath.Join(dir, "raw-agent.json"))
	if string(before) != string(after) {
		t.Fatal("empty failure run rewrote the richer partial transcript")
	}
	var doc RawAgentDocument
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Messages) != 2 || doc.Steps != 3 || doc.ErrorClass != ErrClassStepBudget {
		t.Fatalf("richer partial transcript lost: %+v", doc)
	}
}

// TestWriteFailureRicherRunRefreshesPartial: a later failure that carries
// real run state still refreshes a partial transcript — the guard protects
// only complete records and records the caller cannot match.
func TestWriteFailureRicherRunRefreshesPartial(t *testing.T) {
	out := t.TempDir()
	in := inputForID(t, "scanner-123")
	w := ArtifactWriter{Clock: artifactClock()}
	if _, err := w.WriteFailure(context.Background(), out, in, AgentRun{}, errors.New("early failure"), nil); err != nil {
		t.Fatalf("WriteFailure: %v", err)
	}
	run := AgentRun{
		RawMessages: []llm.ChatMessage{{Role: "user", Content: "finding data"}},
		Steps:       1,
		ErrorClass:  ErrClassProvider,
	}
	if _, err := w.WriteFailure(context.Background(), out, in, run, errors.New("agenttriage: chat: llm status 500"), nil); err != nil {
		t.Fatalf("WriteFailure(run): %v", err)
	}
	name, _ := RunDirName("scanner-123")
	var doc RawAgentDocument
	if err := json.Unmarshal(mustRead(t, filepath.Join(out, name, "raw-agent.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Steps != 1 || doc.ErrorClass != ErrClassProvider || len(doc.Messages) != 1 {
		t.Fatalf("newer run state must replace the thin partial record: %+v", doc)
	}
}

// TestClaimRunDirConcurrent pins the atomic claim: N processes racing to
// claim one directory with DIFFERENT finding IDs — exactly one must win,
// the rest get the ownership error, and the recorded owner is a single
// consistent value (never a torn or mixed claim).
func TestClaimRunDirConcurrent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "raced")
	const n = 16
	var wg sync.WaitGroup
	won := make(chan string, n)
	lost := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			id := fmt.Sprintf("finding-%d", k)
			if err := claimRunDir(dir, id); err != nil {
				lost <- err
			} else {
				won <- id
			}
		}(i)
	}
	wg.Wait()
	close(won)
	close(lost)
	var winners []string
	for id := range won {
		winners = append(winners, id)
	}
	if len(winners) != 1 {
		t.Fatalf("expected exactly 1 winner, got %d: %v", len(winners), winners)
	}
	for err := range lost {
		if !strings.Contains(err.Error(), "already belongs to finding") && !strings.Contains(err.Error(), "just claimed") {
			t.Fatalf("loser got unexpected error: %v", err)
		}
	}
	// The pinned owner file must name the sole winner.
	owner, err := os.ReadFile(filepath.Join(dir, ".owner"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(owner)) != winners[0] {
		t.Fatalf(".owner = %q, want %q", owner, winners[0])
	}
}

// TestWriteFailureLeavesNoPrimaryResultAnnouncement: the primary result is
// announced only after the action package landed. A run that completes the
// investigation write and then fails during the decision write must leave
// stdout silent — the earlier investigation artifacts are not a completed
// result, and a later failure never follows a successful-looking line.
func TestWriteFailureLeavesNoPrimaryResultAnnouncement(t *testing.T) {
	ctx := context.Background()
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	var stdout strings.Builder
	w := ArtifactWriter{Clock: artifactClock(), Stdout: &stdout}
	art, err := w.Write(ctx, out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("Write announced the primary result before the decision existed: %q", stdout.String())
	}
	var stored Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil {
		t.Fatal(err)
	}
	pkg, err := Composer{RulesetHash: strings.Repeat("07", 32)}.Compose(
		ctx, decisionStage0(in, manifest), stored, *stored.FactValidationDetail, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	// Break the final rename after decision.json was staged: the write must
	// roll back and announce nothing.
	if err := os.MkdirAll(filepath.Join(art.RootDir, "decision.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecision(ctx, out, pkg); err == nil {
		t.Fatal("expected WriteDecision to fail")
	}
	if stdout.Len() != 0 {
		t.Fatalf("a failed decision write left a successful primary-result announcement: %q", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(art.RootDir, "decision.json")); !os.IsNotExist(err) {
		t.Fatal("decision.json survived the failed write")
	}
}

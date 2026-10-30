package research

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// replayAnswerText is the retained assistant text used by the replay
// fixtures: prose followed by the single prompt-contract JSON object.
func replayAnswerText(category, reasoning string, assessment map[string]any) []byte {
	ans := map[string]any{"category": category, "reasoning": reasoning}
	if assessment != nil {
		ans["assessment"] = assessment
	}
	b, err := json.Marshal(ans)
	if err != nil {
		panic(err)
	}
	return append([]byte("final answer:\n"), b...)
}

func shaOfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeReplayRun persists a synthetic research run directory in the exact
// on-disk shape a real run leaves behind: report.json (closed schema),
// run-manifest.json and the attempt's answer.txt/result.json files.
func writeReplayRun(t *testing.T, rep *Report, manifest map[string]any, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	rb, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	if manifest != nil {
		mb, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "run-manifest.json"), mb, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, b := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// replayFixture builds a consistent OK persisted run: the recorded
// artifact pins always match the bytes written to disk.
func replayFixture(t *testing.T) (dir string, answerText []byte) {
	t.Helper()
	answerText = replayAnswerText("code_not_reachable",
		"the affected package is imported but the defective entrypoint is never called",
		map[string]any{
			"vulnerability_mechanism": "IPv6 enabled on an IPv4-only interface",
			"attack_scenario":         "requires a runtime network create call",
			"triage_recommendation":   map[string]any{"action": "needs review"},
		})
	result := []byte(`{"info":{"id":"ses_1"},"messages":[]}`)
	answerSHA, resultSHA := shaOfBytes(answerText), shaOfBytes(result)
	answerArt := &AttemptArtifact{
		Path: "agent/attempt-0002/answer.txt", SHA256: answerSHA,
		SizeBytes: int64(len(answerText)), Selector: "assistant text",
	}
	resultArt := &AttemptArtifact{
		Path: "agent/attempt-0002/result.json", SHA256: resultSHA,
		SizeBytes: int64(len(result)), Selector: "raw harness result",
	}
	ext := &Extraction{
		Status: ExtractionValid, InvalidReason: InvalidNone,
		CandidateCount: 1,
		Candidates: []ExtractionCandidate{{
			Index: 0, Status: "VALID", Category: strPtr("code_not_reachable"),
			RawSHA256: strings.Repeat("11", 32), CanonicalSHA256: strings.Repeat("22", 32),
			Selector: "bytes 14..250 of retained answer",
		}},
		SelectedIndex: 0, AnswerArtifact: answerArt,
	}
	rep := &Report{
		Schema: ReportSchema,
		Run: RunInfo{
			RunID: "research-CVE-2099-0001-1700000000",
			Attempts: []Attempt{{
				ID: "attempt-0001", Kind: "deterministic", Ordinal: 1, Status: "OK",
				StartedAt: "2026-10-01T10:00:00Z", FinishedAt: "2026-10-01T10:01:00Z",
				ReasonCode: AttemptReasonInitial, Reason: "initial deterministic lane pass",
				OriginalPreserved: true,
			}, {
				ID: "attempt-0002", Kind: "agent", Ordinal: 2, Status: AgentOK,
				StartedAt: "2026-10-01T10:05:00Z", FinishedAt: "2026-10-01T10:07:00Z",
				ReasonCode: AttemptReasonInitial, Reason: "initial agent assessment",
				OriginalPreserved: true, ResultArtifact: resultArt, Extraction: ext,
			}},
		},
		AgentOutput: AgentOutput{
			Status:         AgentOK,
			Category:       strPtr("code_not_reachable"),
			Reasoning:      strPtr("the affected package is imported but the defective entrypoint is never called"),
			RawArtifact:    AgentRawArtifact{Path: strPtr("agent/attempt-0002/answer.txt"), SHA256: strPtr(answerSHA)},
			AttemptID:      strPtr("attempt-0002"),
			ResultArtifact: resultArt,
			AnswerArtifact: answerArt,
			Extraction:     ext,
		},
	}
	manifest := map[string]any{
		"schema": "research-run-manifest/1", "run_id": "research-CVE-2099-0001-1700000000",
		"agent": map[string]any{
			"model": "qwen3.6-35b", "provider": "legacy-label", "status": "OK", "error": "",
			"manifest": map[string]any{"prompt_path": "eval/agent7/prompts/r0-v1.txt"},
		},
	}
	dir = writeReplayRun(t, rep, manifest, map[string][]byte{
		"agent/attempt-0002/answer.txt":  answerText,
		"agent/attempt-0002/result.json": result,
	})
	return dir, answerText
}

func replayAgentRow(r *Report) *Attempt {
	for i := range r.Run.Attempts {
		if r.Run.Attempts[i].Kind == "agent" {
			return &r.Run.Attempts[i]
		}
	}
	return nil
}

func TestReplayLoad_OKPreservesRecordedOutput(t *testing.T) {
	dir, answerText := replayFixture(t)
	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("loadPersistedAgentTurn: %v", err)
	}
	if turn.Output.Status != AgentOK {
		t.Fatalf("status = %s", turn.Output.Status)
	}
	if turn.Output.Category == nil || *turn.Output.Category != "code_not_reachable" {
		t.Fatalf("category not preserved: %+v", turn.Output.Category)
	}
	if turn.Provider != "legacy-label" || turn.Model != "qwen3.6-35b" {
		t.Fatalf("recorded provider/model not restored verbatim: %q/%q", turn.Provider, turn.Model)
	}
	if turn.Output.Extraction == nil || turn.Output.Extraction.SelectedIndex != 0 ||
		turn.Output.Extraction.CandidateCount != 1 {
		t.Fatalf("extraction record not preserved: %+v", turn.Output.Extraction)
	}
	if turn.Answer == nil {
		t.Fatal("re-parsed answer missing on an OK replay")
	}
	rf := turn.Output.ReplayedFrom
	if rf == nil {
		t.Fatal("replayed_from provenance not recorded")
	}
	abs, _ := filepath.Abs(dir)
	if rf.Dir != abs || rf.OriginalRunID != "research-CVE-2099-0001-1700000000" ||
		rf.OriginalAttemptID != "attempt-0002" {
		t.Fatalf("replayed_from = %+v", rf)
	}
	if rf.AnswerSHA256 != shaOfBytes(answerText) || rf.ResultSHA256 == "" {
		t.Fatalf("replayed_from digests wrong: %+v", rf)
	}
	if turn.ReplayedAttempt == nil || turn.ReplayedAttempt.ID != "attempt-0002" {
		t.Fatalf("persisted attempt row not carried: %+v", turn.ReplayedAttempt)
	}

	lane := fakeLane(t)
	lane.SnapshotRoot = t.TempDir()
	r := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-replay",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	// agent_output survives verbatim plus provenance.
	if r.AgentOutput.Status != AgentOK ||
		r.AgentOutput.AnswerArtifact == nil ||
		r.AgentOutput.AnswerArtifact.SHA256 != shaOfBytes(answerText) {
		t.Fatalf("agent_output mutated on replay: %+v", r.AgentOutput)
	}
	if r.AgentOutput.AttemptID == nil || *r.AgentOutput.AttemptID != "attempt-0002" {
		t.Fatalf("agent_output.attempt_id does not resolve to the replayed row: %+v", r.AgentOutput.AttemptID)
	}
	ag := replayAgentRow(r)
	if ag == nil {
		t.Fatal("no agent attempt row in the rebuilt ledger")
	}
	if ag.ReasonCode != AttemptReasonManualRecheck {
		t.Fatalf("replayed row reason_code = %s", ag.ReasonCode)
	}
	if !strings.Contains(ag.Reason, "replayed from persisted artifacts") ||
		!strings.Contains(ag.Reason, "no model call") {
		t.Fatalf("replayed row reason = %q", ag.Reason)
	}
	if !ag.OriginalPreserved {
		t.Fatal("replayed row must carry original_preserved=true")
	}
	if ag.StartedAt != "2026-10-01T10:05:00Z" || ag.FinishedAt != "2026-10-01T10:07:00Z" {
		t.Fatalf("saved timestamps not preserved: %s..%s", ag.StartedAt, ag.FinishedAt)
	}
	if ag.RetryOf != nil {
		t.Fatal("saved retry_of must not be carried into the replay ledger")
	}
	if ag.Extraction == nil || ag.Extraction.Status != ExtractionValid {
		t.Fatalf("saved extraction not preserved on the ledger row: %+v", ag.Extraction)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("rebuilt replay report failed validation:\n%v", err)
	}
}

func TestReplayLoad_FailClosedOnAnswerDigest(t *testing.T) {
	dir, answerText := replayFixture(t)
	// Corrupt the retained bytes: the recorded pin no longer matches.
	if err := os.WriteFile(filepath.Join(dir, "agent/attempt-0002/answer.txt"),
		append(answerText, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	turn, err := LoadPersistedAgentTurn(dir)
	if err == nil || turn != nil {
		t.Fatalf("corrupted answer.txt replayed: turn=%+v err=%v", turn, err)
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("error does not name the digest mismatch: %v", err)
	}
}

func TestReplayLoad_FailClosedOnMissingPinnedAnswer(t *testing.T) {
	dir, _ := replayFixture(t)
	if err := os.Remove(filepath.Join(dir, "agent/attempt-0002/answer.txt")); err != nil {
		t.Fatal(err)
	}
	turn, err := LoadPersistedAgentTurn(dir)
	if err == nil || turn != nil {
		t.Fatalf("missing pinned answer.txt replayed: turn=%+v err=%v", turn, err)
	}
}

func TestReplayLoad_PreservesInvalidFormatWithoutAnswer(t *testing.T) {
	// The extractor rejected the answer on the original run: the attempt
	// row and agent_output are preserved verbatim — no synthetic
	// assertions, no status rewrite.
	result := []byte(`{"info":{"id":"ses_2"},"messages":[]}`)
	resultSHA := shaOfBytes(result)
	resultArt := &AttemptArtifact{
		Path: "agent/attempt-0002/result.json", SHA256: resultSHA,
		SizeBytes: int64(len(result)), Selector: "raw harness result",
	}
	ext := &Extraction{
		Status: ExtractionInvalid, InvalidReason: InvalidNoCandidate,
		CandidateCount: 0, Candidates: []ExtractionCandidate{}, SelectedIndex: -1,
	}
	rep := &Report{
		Schema: ReportSchema,
		Run: RunInfo{
			RunID: "research-CVE-2099-0002-1700000000",
			Attempts: []Attempt{{
				ID: "attempt-0002", Kind: "agent", Ordinal: 2, Status: AgentInvalidFormat,
				StartedAt: "2026-10-02T09:00:00Z", FinishedAt: "2026-10-02T09:01:30Z",
				ReasonCode:        AttemptReasonInvalidExtraction,
				Reason:            "answer extraction failed: no assistant text part in result.json",
				OriginalPreserved: true,
				ResultArtifact:    resultArt,
				Extraction:        ext,
			}},
		},
		AgentOutput: AgentOutput{
			Status:         AgentInvalidFormat,
			AttemptID:      strPtr("attempt-0002"),
			ResultArtifact: resultArt,
			Extraction:     ext,
		},
	}
	manifest := map[string]any{
		"schema": "research-run-manifest/1", "run_id": "research-CVE-2099-0002-1700000000",
		"agent": map[string]any{
			"status": "INVALID_FORMAT",
			"error":  "no assistant text part in result.json",
		},
	}
	dir := writeReplayRun(t, rep, manifest, map[string][]byte{
		"agent/attempt-0002/result.json": result,
	})
	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("INVALID_FORMAT replay failed: %v", err)
	}
	if turn.Output.Status != AgentInvalidFormat {
		t.Fatalf("status rewritten: %s", turn.Output.Status)
	}
	if turn.Answer != nil {
		t.Fatal("synthetic answer materialized on an INVALID_FORMAT replay")
	}
	if turn.Err != "no assistant text part in result.json" {
		t.Fatalf("operator error not restored from manifest: %q", turn.Err)
	}
	if turn.Output.ReplayedFrom == nil || turn.Output.ReplayedFrom.AnswerSHA256 != "" {
		t.Fatalf("bad provenance: %+v", turn.Output.ReplayedFrom)
	}

	r := Assemble(AssembleInput{
		Lane: fakeLane(t), Turn: turn, RunID: "research-replay-inv",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.AgentOutput.Status != AgentInvalidFormat {
		t.Fatalf("assembled status rewritten: %s", r.AgentOutput.Status)
	}
	ag := replayAgentRow(r)
	if ag == nil || ag.Status != AgentInvalidFormat || ag.ReasonCode != AttemptReasonManualRecheck {
		t.Fatalf("replayed ledger row wrong: %+v", ag)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("INVALID_FORMAT replay report failed validation:\n%v", err)
	}
}

func TestValidate_ReplayedFromRequiresAnswerDigest(t *testing.T) {
	// A replayed report whose persisted record pins an answer artifact
	// must carry the retained-answer digest.
	r := validReport(t)
	r.AgentOutput.Status = AgentOK
	r.AgentOutput.Category = strPtr("uncertain")
	r.AgentOutput.Reasoning = strPtr("saved reasoning")
	agRow := replayAgentRow(r)
	agRow.Status = AgentOK
	agRow.StartedAt = "2026-10-01T10:05:00Z"
	agRow.FinishedAt = "2026-10-01T10:07:00Z"
	agRow.ReasonCode = AttemptReasonManualRecheck
	agRow.Reason = "replayed from persisted artifacts (x); no model call"
	ansSHA := strings.Repeat("ab", 32)
	r.AgentOutput.AnswerArtifact = &AttemptArtifact{
		Path: "agent/attempt-0002/answer.txt", SHA256: ansSHA, SizeBytes: 7,
	}
	r.AgentOutput.RawArtifact = AgentRawArtifact{
		Path: strPtr("agent/attempt-0002/answer.txt"), SHA256: strPtr(ansSHA),
	}
	r.AgentOutput.AttemptID = strPtr("attempt-0002")
	r.AgentOutput.ReplayedFrom = &AgentReplayProvenance{Dir: "/old/run"}
	if err := Validate(r, ""); err == nil ||
		!strings.Contains(err.Error(), "replayed_from.answer_sha256") {
		t.Fatalf("missing answer digest not rejected: %v", err)
	}
	// With the digest recorded the replay provenance checks pass.
	r.AgentOutput.ReplayedFrom.AnswerSHA256 = ansSHA
	if err := Validate(r, ""); err != nil {
		t.Fatalf("complete replayed_from rejected:\n%v", err)
	}
}

func TestValidate_ReplayedFromRejectsLiveTurnMarkers(t *testing.T) {
	r := validReport(t)
	r.AgentOutput.AttemptID = strPtr("attempt-0002")
	agRow := replayAgentRow(r)
	agRow.Status = AgentOK
	agRow.ReasonCode = AttemptReasonManualRecheck
	agRow.Reason = "replayed from persisted artifacts (x); no model call"
	r.AgentOutput.ReplayedFrom = &AgentReplayProvenance{Dir: "/old/run"}
	// Live-run pins must not co-exist with replay provenance.
	r.Run.Harness.PromptSHA256 = strPtr(strings.Repeat("ef", 32))
	if err := Validate(r, ""); err == nil ||
		!strings.Contains(err.Error(), "harness pins") {
		t.Fatalf("replayed_from with live harness pins not rejected: %v", err)
	}
}

// rewriteReport rewrites the persisted report.json after fn mutates it.
// Note the fixture's artifact structs are shared pointers across
// agent_output and the attempt row — conflicting-record scenarios must
// replace the pointer, never mutate fields in place.
func rewriteReport(t *testing.T, dir string, fn func(*Report)) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ParseReport(b)
	if err != nil {
		t.Fatal(err)
	}
	fn(rep)
	rb, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReplayLoad_ConflictingArtifactPins(t *testing.T) {
	// agent_output.answer_artifact and the legacy raw_artifact pin the
	// same path — a digest disagreement is a corrupted persisted report.
	dir, _ := replayFixture(t)
	rewriteReport(t, dir, func(r *Report) {
		r.AgentOutput.RawArtifact.SHA256 = strPtr(strings.Repeat("99", 32))
	})
	if _, err := LoadPersistedAgentTurn(dir); err == nil ||
		!strings.Contains(err.Error(), "conflicting sha256 pins") {
		t.Fatalf("conflicting answer/raw pins not rejected: %v", err)
	}
	// Same digest but disagreeing recorded size metadata on the same
	// path is still an inconsistent record — rejected before any byte
	// verification could pick a winner.
	dir2, answerText := replayFixture(t)
	rewriteReport(t, dir2, func(r *Report) {
		r.Run.Attempts[1].Extraction.AnswerArtifact = &AttemptArtifact{
			Path:      "agent/attempt-0002/answer.txt",
			SHA256:    shaOfBytes(answerText),
			SizeBytes: int64(len(answerText)) + 1,
			Selector:  "assistant text",
		}
	})
	if _, err := LoadPersistedAgentTurn(dir2); err == nil ||
		!strings.Contains(err.Error(), "conflicting size_bytes pins") {
		t.Fatalf("conflicting size pins not rejected: %v", err)
	}
}

func TestReplayLoad_AttemptSelectionRules(t *testing.T) {
	// Without agent_output.attempt_id, more than one persisted agent row
	// makes the provenance ambiguous — fail closed.
	dir, _ := replayFixture(t)
	rewriteReport(t, dir, func(r *Report) {
		r.AgentOutput.AttemptID = nil
		second := r.Run.Attempts[1]
		second.ID = "attempt-0003"
		second.Ordinal = 3
		r.Run.Attempts = append(r.Run.Attempts, second)
	})
	if _, err := LoadPersistedAgentTurn(dir); err == nil ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous attempt set not rejected: %v", err)
	}
	// agent_output and the selected ledger row record the same attempt:
	// a status disagreement is a corrupted persisted report.
	dir2, _ := replayFixture(t)
	rewriteReport(t, dir2, func(r *Report) {
		r.Run.Attempts[1].Status = AgentFailed
	})
	if _, err := LoadPersistedAgentTurn(dir2); err == nil ||
		!strings.Contains(err.Error(), "disagrees with the persisted attempt") {
		t.Fatalf("status mismatch not rejected: %v", err)
	}
}

func TestReplayLoad_RejectedInputs(t *testing.T) {
	// Missing report.json.
	empty := t.TempDir()
	if _, err := LoadPersistedAgentTurn(empty); err == nil {
		t.Fatal("replay without report.json accepted")
	}
	// No persisted agent attempt row.
	dir, _ := replayFixture(t)
	b, _ := os.ReadFile(filepath.Join(dir, "report.json"))
	rep, err := ParseReport(b)
	if err != nil {
		t.Fatal(err)
	}
	rep.Run.Attempts = rep.Run.Attempts[:1] // drop the agent row
	rb, _ := json.Marshal(rep)
	if err := os.WriteFile(filepath.Join(dir, "report.json"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPersistedAgentTurn(dir); err == nil ||
		!strings.Contains(err.Error(), "attempt_id") {
		t.Fatalf("dangling attempt_id not rejected: %v", err)
	}
	// Recorded OK but the pinned bytes no longer extract: inconsistent
	// persisted state must fail closed, not silently degrade.
	dir2, _ := replayFixture(t)
	garbage := []byte("not a json answer at all")
	gSHA := shaOfBytes(garbage)
	rep2b, _ := os.ReadFile(filepath.Join(dir2, "report.json"))
	rep2, _ := ParseReport(rep2b)
	rep2.AgentOutput.AnswerArtifact.SHA256 = gSHA
	rep2.AgentOutput.RawArtifact.SHA256 = strPtr(gSHA)
	rep2.Run.Attempts[1].Extraction.AnswerArtifact.SHA256 = gSHA
	rep2.AgentOutput.Extraction.AnswerArtifact.SHA256 = gSHA
	rb2, _ := json.Marshal(rep2)
	if err := os.WriteFile(filepath.Join(dir2, "report.json"), rb2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "agent/attempt-0002/answer.txt"), garbage, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPersistedAgentTurn(dir2); err == nil {
		t.Fatal("recorded OK with unparseable retained answer replayed")
	}
}

// §2.7 recovery parity: replay runs the same strictExtract+recovery
// ladder as the live path — an OK turn whose retained answer only
// survives via bounded recovery still materializes the pinned answer,
// while a recorded INVALID_FORMAT is preserved verbatim even when the
// current extractor could recover the answer bytes.
func TestReplay_ExtractorRecovery(t *testing.T) {
	// (a) OK run, answer recoverable only through brace completion.
	dir, answerText := replayFixture(t)
	trunc := answerText[:len(answerText)-1] // retained bytes lost their final '}'
	truncSHA := shaOfBytes(trunc)
	if err := os.WriteFile(filepath.Join(dir, "agent", "attempt-0002", "answer.txt"), trunc, 0o644); err != nil {
		t.Fatal(err)
	}
	rewriteReport(t, dir, func(r *Report) {
		art := &AttemptArtifact{
			Path: "agent/attempt-0002/answer.txt", SHA256: truncSHA,
			SizeBytes: int64(len(trunc)), Selector: "assistant text",
		}
		ext := &Extraction{
			Status: ExtractionValid, InvalidReason: InvalidNone,
			CandidateCount: 1,
			Candidates: []ExtractionCandidate{{
				Index: 0, Status: "VALID", Category: strPtr("code_not_reachable"),
				RawSHA256: strings.Repeat("33", 32), CanonicalSHA256: strings.Repeat("44", 32),
				Selector: "bytes 14..end of retained answer",
			}},
			SelectedIndex: 0, Recovery: RecoveryBraceCompletion, AnswerArtifact: art,
		}
		// Replace pointers, never mutate: fixture artifacts are shared.
		ag := replayAgentRow(r)
		ag.Extraction = ext
		r.AgentOutput.Extraction = ext
		r.AgentOutput.AnswerArtifact = art
		r.AgentOutput.RawArtifact = AgentRawArtifact{
			Path: strPtr("agent/attempt-0002/answer.txt"), SHA256: strPtr(truncSHA),
		}
	})
	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("recoverable OK replay failed: %v", err)
	}
	if turn.Answer == nil || turn.Answer.Category != "code_not_reachable" {
		t.Fatalf("recovery ladder did not run on replay: %+v", turn.Answer)
	}
	if turn.Output.Status != AgentOK {
		t.Fatalf("recorded status changed: %s", turn.Output.Status)
	}

	r := Assemble(AssembleInput{
		Lane: fakeLane(t), Turn: turn, RunID: "research-replay-rec",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	ag := replayAgentRow(r)
	if ag == nil || ag.Extraction == nil || ag.Extraction.Recovery != RecoveryBraceCompletion {
		t.Fatalf("recorded recovery marker lost on the ledger: %+v", ag)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("recovered replay report failed validation:\n%v", err)
	}

	// (b) INVALID_FORMAT run whose retained answer would now recover:
	// the recorded status is preserved, no answer is synthesized.
	result := []byte(`{"info":{"id":"ses_r"},"messages":[]}`)
	resultSHA := shaOfBytes(result)
	broken := []byte(`{"category":"vulnerable","reasoning":"vulnerable vendored code confirmed","assessment":{"x":1`)
	brokenSHA := shaOfBytes(broken)
	resultArt := &AttemptArtifact{
		Path: "agent/attempt-0002/result.json", SHA256: resultSHA,
		SizeBytes: int64(len(result)), Selector: "raw harness result",
	}
	answerArt := &AttemptArtifact{
		Path: "agent/attempt-0002/answer.txt", SHA256: brokenSHA,
		SizeBytes: int64(len(broken)), Selector: "assistant text",
	}
	badExt := &Extraction{
		Status: ExtractionInvalid, InvalidReason: InvalidNoCandidate,
		CandidateCount: 0, Candidates: []ExtractionCandidate{}, SelectedIndex: -1,
		AnswerArtifact: answerArt,
	}
	rep := &Report{
		Schema: ReportSchema,
		Run: RunInfo{
			RunID: "research-CVE-2099-0003-1700000000",
			Attempts: []Attempt{{
				ID: "attempt-0002", Kind: "agent", Ordinal: 2, Status: AgentInvalidFormat,
				StartedAt: "2026-10-03T09:00:00Z", FinishedAt: "2026-10-03T09:01:30Z",
				ReasonCode:        AttemptReasonInvalidExtraction,
				Reason:            "answer extraction invalid (NO_CANDIDATE): 0 candidate(s) retained",
				OriginalPreserved: true,
				ResultArtifact:    resultArt,
				Extraction:        badExt,
			}},
		},
		AgentOutput: AgentOutput{
			Status:         AgentInvalidFormat,
			AttemptID:      strPtr("attempt-0002"),
			ResultArtifact: resultArt,
			AnswerArtifact: answerArt,
			Extraction:     badExt,
		},
	}
	manifest := map[string]any{
		"schema": "research-run-manifest/1", "run_id": "research-CVE-2099-0003-1700000000",
		"agent": map[string]any{
			"status": "INVALID_FORMAT",
			"error":  "answer extraction invalid (NO_CANDIDATE): 0 candidate(s) retained",
		},
	}
	badDir := writeReplayRun(t, rep, manifest, map[string][]byte{
		"agent/attempt-0002/answer.txt":  broken,
		"agent/attempt-0002/result.json": result,
	})
	turn, err = LoadPersistedAgentTurn(badDir)
	if err != nil {
		t.Fatalf("INVALID_FORMAT replay failed: %v", err)
	}
	if turn.Output.Status != AgentInvalidFormat {
		t.Fatalf("recorded INVALID_FORMAT rewritten to %s", turn.Output.Status)
	}
	if turn.Answer != nil {
		t.Fatal("recoverable answer retroactively materialized on a non-OK replay")
	}
	if turn.Output.ReplayedFrom == nil || turn.Output.ReplayedFrom.AnswerSHA256 != brokenSHA {
		t.Fatalf("bad provenance: %+v", turn.Output.ReplayedFrom)
	}
	r = Assemble(AssembleInput{
		Lane: fakeLane(t), Turn: turn, RunID: "research-replay-broken",
		StartedAt: time.Now(), FinishedAt: time.Now(),
	})
	if r.AgentOutput.Status != AgentInvalidFormat {
		t.Fatalf("assembled status rewritten: %s", r.AgentOutput.Status)
	}
	ag = replayAgentRow(r)
	if ag == nil || ag.Status != AgentInvalidFormat || ag.Extraction == nil ||
		ag.Extraction.Status != ExtractionInvalid || ag.Extraction.Recovery != "" {
		t.Fatalf("broken replay ledger row wrong: %+v", ag)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("broken replay report failed validation:\n%v", err)
	}
}

// replayFixtureV3 writes a persisted run whose report.json is a real
// assembled slice2-fidelity/3 document: the persisted evidence_level is
// the value the assembler derived, every verified-fact artifact pin is
// rewritten to the sha256 of the bytes written next to the report, and
// observations.jsonl is populated — exactly what a live --replay-able
// run leaves on disk. status selects the recorded agent outcome:
// AgentOK retains an answer.txt that strictExtract re-parses; any other
// status records the saved extraction verbatim and pins only the raw
// result artifact.
func replayFixtureV3(t *testing.T, status string) (dir string, persisted *Report, answerText []byte) {
	t.Helper()
	return replayFixtureV3Lane(t, fakeLane(t), status)
}

// replayFixtureV3Lane is replayFixtureV3 over a caller-supplied lane:
// the persisted report is assembled from exactly the lane's
// observations/facts, so a lane that records package-usage evidence
// persists those conditions, facts and evidence_level derivations.
func replayFixtureV3Lane(t *testing.T, lane *LaneResult, status string) (dir string, persisted *Report, answerText []byte) {
	t.Helper()
	result := []byte(`{"info":{"id":"ses_v3"},"messages":[]}`)
	resultSHA := shaOfBytes(result)
	resultArt := &AttemptArtifact{
		Path: "agent/attempt-0002/result.json", SHA256: resultSHA,
		SizeBytes: int64(len(result)), Selector: "raw harness result",
	}
	turn := &AgentTurn{
		Output:    AgentOutput{Status: status},
		StartedAt: time.Date(2026, 10, 5, 10, 5, 0, 0, time.UTC),
		// The saved timestamps stay distinct from the deterministic row's.
		FinishedAt:     time.Date(2026, 10, 5, 10, 7, 0, 0, time.UTC),
		ResultArtifact: resultArt,
	}
	files := map[string][]byte{"agent/attempt-0002/result.json": result}
	if status == AgentOK {
		answerText = replayAnswerText("code_not_reachable",
			"the affected package is imported but the defective entrypoint is never called",
			map[string]any{
				"vulnerability_mechanism": "IPv6 enabled on an IPv4-only interface",
				"attack_scenario":         "requires a runtime network create call",
				"triage_recommendation":   map[string]any{"action": "needs review"},
			})
		ans, ext := strictExtract(string(answerText))
		if ans == nil || ext == nil || ext.Status != ExtractionValid {
			t.Fatalf("fixture answer does not extract VALID: ans=%+v ext=%+v", ans, ext)
		}
		answerArt := &AttemptArtifact{
			Path: "agent/attempt-0002/answer.txt", SHA256: shaOfBytes(answerText),
			SizeBytes: int64(len(answerText)), Selector: "assistant text",
		}
		ext.AnswerArtifact = answerArt
		turn.Answer = ans
		turn.AnswerJSON = answerText
		turn.Output.Category = strPtr(ans.Category)
		turn.Output.Reasoning = strPtr(ans.Reasoning)
		turn.Output.RawArtifact = AgentRawArtifact{
			Path: strPtr(answerArt.Path), SHA256: strPtr(answerArt.SHA256),
		}
		turn.AnswerArtifact = answerArt
		turn.Extraction = ext
		files[answerArt.Path] = answerText
	} else {
		turn.Err = "harness reported the attempt failed"
		turn.Extraction = &Extraction{
			Status: ExtractionInvalid, InvalidReason: InvalidNoCandidate,
			CandidateCount: 0, Candidates: []ExtractionCandidate{}, SelectedIndex: -1,
		}
	}
	rep := Assemble(AssembleInput{
		Lane: lane, Turn: turn, RunID: "research-CVE-2099-0042-1700000000",
		StartedAt:  time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 10, 5, 10, 8, 0, 0, time.UTC),
	})
	if !slices.Contains(rep.ContractExtensions, Slice2ExtensionV3) {
		t.Fatalf("fixture report lacks %s: %v", Slice2ExtensionV3, rep.ContractExtensions)
	}
	if rep.EvidenceLevel == nil {
		t.Fatal("assembled fixture lost its derived evidence_level")
	}
	// Repin every recorded fact artifact at bytes this fixture writes —
	// the loader's /3 gate revalidates the persisted report dir-scoped,
	// so fabricated digests must be replaced with real ones.
	for i := range rep.VerifiedFacts {
		b := []byte("observation record " + rep.VerifiedFacts[i].Provenance.ObservationID)
		rep.VerifiedFacts[i].Artifact.SHA256 = shaOfBytes(b)
		files[rep.VerifiedFacts[i].Artifact.Path] = b
	}
	var obsRows [][]byte
	for _, o := range lane.Observations {
		row, merr := json.Marshal(map[string]any{"observation_id": o.ID})
		if merr != nil {
			t.Fatal(merr)
		}
		obsRows = append(obsRows, row)
	}
	files["observations.jsonl"] = bytes.Join(obsRows, []byte("\n"))
	manifest := map[string]any{
		"schema": "research-run-manifest/1", "run_id": rep.Run.RunID,
		"agent": map[string]any{
			"status": status, "error": turn.Err,
			"manifest": map[string]any{"prompt_path": "eval/agent7/prompts/r0-v1.txt"},
		},
	}
	dir = writeReplayRun(t, rep, manifest, files)
	// Self-check: the fixture must satisfy exactly the gate the loader
	// applies — the full contract including the recomputed evidence_level.
	saved, perr := ParseReport(mustReadReport(t, dir))
	if perr != nil {
		t.Fatal(perr)
	}
	if verr := Validate(saved, dir); verr != nil {
		t.Fatalf("v3 persisted fixture fails the input gate:\n%v", verr)
	}
	return dir, saved, answerText
}

func mustReadReport(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReplayEvidenceLevel_V3LoadsAndDerives — the happy path: a persisted
// /3 run loads, every recorded member is preserved verbatim, the re-
// assembled report recomputes evidence_level through the shared pure
// derivation (never the persisted object), and no harness/model pins
// appear — proof the replay path performs no model call.
func TestReplayEvidenceLevel_V3LoadsAndDerives(t *testing.T) {
	dir, saved, answerText := replayFixtureV3(t, AgentOK)
	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("/3 replay load failed: %v", err)
	}
	if turn.Output.Status != AgentOK || turn.Answer == nil {
		t.Fatalf("recorded OK turn not restored: %+v", turn.Output)
	}
	if turn.ReplayedAttempt == nil || turn.ReplayedAttempt.Status != AgentOK {
		t.Fatalf("persisted attempt not carried verbatim: %+v", turn.ReplayedAttempt)
	}

	r := Assemble(AssembleInput{
		Lane: fakeLane(t), Turn: turn, RunID: "research-replay-v3",
		StartedAt:  time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 10, 6, 9, 1, 0, 0, time.UTC),
	})
	// The replayed ladder is recomputed from this run's facts and
	// conditions — never carried from the persisted report — and it is
	// exactly what the shared pure derivation yields for the new report.
	if r.EvidenceLevel == nil {
		t.Fatal("replayed /3 report has no evidence_level")
	}
	want := deriveEvidenceLevel(r)
	got := r.EvidenceLevel
	if got.Level != want.Level || got.Basis != want.Basis ||
		got.Statement != want.Statement || got.Scope != want.Scope ||
		!slices.Equal(got.ConditionRefs, want.ConditionRefs) ||
		!slices.Equal(got.EvidenceRefs, want.EvidenceRefs) ||
		!slices.Equal(got.BlockingConditions, want.BlockingConditions) ||
		!slices.Equal(got.Limitations, want.Limitations) {
		t.Fatalf("replayed evidence_level was not recomputed through deriveEvidenceLevel: %+v vs %+v", got, want)
	}
	// Recorded agent/extraction status, artifacts and digests verbatim.
	if r.AgentOutput.Status != saved.AgentOutput.Status {
		t.Fatalf("saved status %s rewritten to %s", saved.AgentOutput.Status, r.AgentOutput.Status)
	}
	if r.AgentOutput.Extraction == nil || saved.AgentOutput.Extraction == nil ||
		r.AgentOutput.Extraction.Status != saved.AgentOutput.Extraction.Status ||
		r.AgentOutput.Extraction.SelectedIndex != saved.AgentOutput.Extraction.SelectedIndex {
		t.Fatalf("saved extraction not preserved: %+v vs %+v", r.AgentOutput.Extraction, saved.AgentOutput.Extraction)
	}
	if r.AgentOutput.AnswerArtifact == nil || r.AgentOutput.AnswerArtifact.SHA256 != shaOfBytes(answerText) {
		t.Fatalf("answer artifact pin changed: %+v", r.AgentOutput.AnswerArtifact)
	}
	if r.AgentOutput.ResultArtifact == nil ||
		r.AgentOutput.ResultArtifact.SHA256 != saved.AgentOutput.ResultArtifact.SHA256 {
		t.Fatalf("result artifact pin changed: %+v", r.AgentOutput.ResultArtifact)
	}
	ag := replayAgentRow(r)
	if ag == nil || ag.ID != "attempt-0002" || ag.Status != AgentOK {
		t.Fatalf("replayed ledger row wrong: %+v", ag)
	}
	if ag.StartedAt != "2026-10-05T10:05:00Z" || ag.FinishedAt != "2026-10-05T10:07:00Z" {
		t.Fatalf("saved timestamps not preserved: %s..%s", ag.StartedAt, ag.FinishedAt)
	}
	if ag.Extraction == nil || ag.Extraction.Status != ExtractionValid {
		t.Fatalf("saved extraction not preserved on the ledger row: %+v", ag.Extraction)
	}
	// No model call happened: a replayed run carries no live harness pins.
	if r.Run.Harness != (HarnessInfo{}) {
		t.Fatalf("replay produced live harness pins: %+v", r.Run.Harness)
	}
	if r.AgentOutput.ReplayedFrom == nil {
		t.Fatal("replayed_from provenance missing")
	}
	if r.Disposition.Class != "REVIEW_REQUIRED" || r.Disposition.AutoClose {
		t.Fatalf("disposition mutated: %+v", r.Disposition)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("replayed /3 report failed validation:\n%v", err)
	}
}

// TestReplayEvidenceLevel_ByteStable — the same persisted input replayed
// and assembled twice yields a byte-identical ladder and a byte-identical
// report.json, and reloading the same directory reproduces the recorded
// agent_output byte-for-byte.
func TestReplayEvidenceLevel_ByteStable(t *testing.T) {
	dir, _, _ := replayFixtureV3(t, AgentOK)
	mk := func() []byte {
		turn, err := LoadPersistedAgentTurn(dir)
		if err != nil {
			t.Fatalf("replay load: %v", err)
		}
		r := Assemble(AssembleInput{
			Lane: fakeLane(t), Turn: turn, RunID: "research-replay-stable",
			StartedAt:  time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
			FinishedAt: time.Date(2026, 10, 6, 9, 1, 0, 0, time.UTC),
		})
		el, err := json.Marshal(r.EvidenceLevel)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(el) {
			t.Fatal("evidence_level did not marshal")
		}
		jb, err := RenderJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		return append(el, jb...)
	}
	if a, b := mk(), mk(); !bytes.Equal(a, b) {
		t.Fatal("identical persisted input produced divergent ladder/report bytes")
	}
	t1, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatal(err)
	}
	o1, _ := json.Marshal(t1.Output)
	o2, _ := json.Marshal(t2.Output)
	if !bytes.Equal(o1, o2) {
		t.Fatal("reloading the same persisted dir produced divergent agent_output bytes")
	}
}

// TestReplayEvidenceLevel_TamperedV3Aborts — every mutation of the
// derived ladder (or the role matrix it rests on) must abort the replay
// at load time: the persisted value is never trusted, it is recomputed
// and compared before any replayed output exists.
func TestReplayEvidenceLevel_TamperedV3Aborts(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*testing.T, *Report)
		wantErr string
	}{
		{"forged level", func(t *testing.T, r *Report) {
			r.EvidenceLevel.Level = EvidenceLevelL3
		}, "evidence_level"},
		{"forged basis", func(t *testing.T, r *Report) {
			r.EvidenceLevel.Basis = EvidenceBasisDynamic
		}, "evidence_level"},
		{"blocking conditions mutated", func(t *testing.T, r *Report) {
			r.EvidenceLevel.BlockingConditions = append(
				slices.Clone(r.EvidenceLevel.BlockingConditions), "EC-bogus")
		}, "blocking_conditions"},
		{"statement edited", func(t *testing.T, r *Report) {
			r.EvidenceLevel.Statement = "forged static-path statement"
		}, "evidence_level"},
		{"role forged on deterministic condition", func(t *testing.T, r *Report) {
			for i := range r.ExploitationConditions {
				if r.ExploitationConditions[i].Origin == OriginDeterm {
					r.ExploitationConditions[i].Role = ConditionRoleSupporting
					return
				}
			}
			t.Fatal("fixture has no deterministic condition to mutate")
		}, "role"},
		{"evidence_level dropped", func(t *testing.T, r *Report) {
			r.EvidenceLevel = nil
		}, "evidence_level"},
		{"marker pairs are still exclusive", func(t *testing.T, r *Report) {
			r.ContractExtensions = append(slices.Clone(r.ContractExtensions), Slice2Extension)
		}, "mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, _ := replayFixtureV3(t, AgentOK)
			rewriteReport(t, dir, func(r *Report) { tc.mutate(t, r) })
			turn, err := LoadPersistedAgentTurn(dir)
			if err == nil || turn != nil {
				t.Fatalf("tampered /3 report replayed: turn=%+v err=%v", turn, err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error does not name the violated field %q: %v", tc.wantErr, err)
			}
		})
	}
}

// TestReplayEvidenceLevel_V3ArtifactPinsStillFailClosed — the /3 input
// gate did not weaken the retained-artifact contract: a missing pinned
// verified-fact artifact, corrupted pinned answer bytes or a missing
// pinned result file all abort the replay.
func TestReplayEvidenceLevel_V3ArtifactPinsStillFailClosed(t *testing.T) {
	dir, saved, _ := replayFixtureV3(t, AgentOK)
	if err := os.Remove(filepath.Join(dir, saved.VerifiedFacts[0].Artifact.Path)); err != nil {
		t.Fatal(err)
	}
	if turn, err := LoadPersistedAgentTurn(dir); err == nil || turn != nil {
		t.Fatalf("missing pinned fact artifact replayed: %v", turn)
	}

	dir, saved, answerText := replayFixtureV3(t, AgentOK)
	ansPath := saved.AgentOutput.AnswerArtifact.Path
	if err := os.WriteFile(filepath.Join(dir, ansPath), append(answerText, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	if turn, err := LoadPersistedAgentTurn(dir); err == nil || turn != nil ||
		!strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("corrupted answer bytes replayed: turn=%+v err=%v", turn, err)
	}

	dir, _, _ = replayFixtureV3(t, AgentOK)
	if err := os.Remove(filepath.Join(dir, "agent/attempt-0002/result.json")); err != nil {
		t.Fatal(err)
	}
	if turn, err := LoadPersistedAgentTurn(dir); err == nil || turn != nil {
		t.Fatalf("missing pinned result.json replayed: %v", turn)
	}
}

// TestReplayEvidenceLevel_NonOKStatusPreservedVerbatim — a recorded
// FAILED /3 turn replays verbatim: status, operator error and the saved
// INVALID extraction survive unchanged, no answer is materialized and
// the ledger row keeps the recorded attempt identity.
func TestReplayEvidenceLevel_NonOKStatusPreservedVerbatim(t *testing.T) {
	dir, saved, _ := replayFixtureV3(t, AgentFailed)
	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("/3 FAILED replay failed: %v", err)
	}
	if turn.Output.Status != AgentFailed {
		t.Fatalf("recorded FAILED rewritten to %s", turn.Output.Status)
	}
	if turn.Err != "harness reported the attempt failed" {
		t.Fatalf("operator error not restored from manifest: %q", turn.Err)
	}
	if turn.Answer != nil || turn.AnswerJSON != nil {
		t.Fatal("an answer was materialized on a non-OK replay")
	}
	if turn.Output.Extraction == nil || saved.AgentOutput.Extraction == nil ||
		turn.Output.Extraction.Status != saved.AgentOutput.Extraction.Status {
		t.Fatalf("saved extraction status not preserved: %+v vs %+v",
			turn.Output.Extraction, saved.AgentOutput.Extraction)
	}

	r := Assemble(AssembleInput{
		Lane: fakeLane(t), Turn: turn, RunID: "research-replay-v3-failed",
		StartedAt:  time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 10, 6, 9, 1, 0, 0, time.UTC),
	})
	if r.AgentOutput.Status != AgentFailed {
		t.Fatalf("assembled status rewritten: %s", r.AgentOutput.Status)
	}
	ag := replayAgentRow(r)
	if ag == nil || ag.Status != AgentFailed || ag.ReasonCode != AttemptReasonManualRecheck {
		t.Fatalf("replayed ledger row wrong: %+v", ag)
	}
	if ag.Extraction == nil || ag.Extraction.Status != ExtractionInvalid {
		t.Fatalf("saved INVALID extraction not preserved on the ledger row: %+v", ag.Extraction)
	}
	if ag.StartedAt != "2026-10-05T10:05:00Z" {
		t.Fatalf("saved attempt identity/timestamps not preserved: %+v", ag)
	}
	if r.EvidenceLevel == nil {
		t.Fatal("replayed /3 report lost its derived evidence_level")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("FAILED /3 replay report failed validation:\n%v", err)
	}
}

// TestReplayEvidenceLevel_LegacyMarkersUnchanged — persisted /1 and /2
// reports, and reports with no slice-2 marker at all, take the existing
// compatibility path: they load without role/evidence_level requirements
// and their recorded turn is preserved verbatim. An evidence_level
// member on a /2 document is inert data — the /3 gate is marker-scoped,
// not field-scoped, exactly like Validate treats it.
func TestReplayEvidenceLevel_LegacyMarkersUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		markers []string
	}{
		{"no marker", nil},
		{"v1", []string{Slice2ExtensionV1}},
		{"v2", []string{Slice2Extension}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := replayFixture(t)
			if tc.markers != nil {
				rewriteReport(t, dir, func(r *Report) {
					r.ContractExtensions = tc.markers
				})
			}
			turn, err := LoadPersistedAgentTurn(dir)
			if err != nil {
				t.Fatalf("legacy (%v) replay rejected: %v", tc.markers, err)
			}
			if turn.Output.Status != AgentOK {
				t.Fatalf("status not preserved: %s", turn.Output.Status)
			}
		})
	}
	t.Run("v2 with inert evidence_level member", func(t *testing.T) {
		dir, _ := replayFixture(t)
		rewriteReport(t, dir, func(r *Report) {
			r.ContractExtensions = []string{Slice2Extension}
			r.EvidenceLevel = &EvidenceLevel{Level: EvidenceLevelL3, Basis: EvidenceBasisDynamic}
		})
		turn, err := LoadPersistedAgentTurn(dir)
		if err != nil {
			t.Fatalf("/2 replay with an inert evidence_level member rejected: %v", err)
		}
		if turn.Output.Status != AgentOK {
			t.Fatalf("status not preserved: %s", turn.Output.Status)
		}
	})
}

func TestReplayLegacyReportDoesNotAcquireR6Fields(t *testing.T) {
	dir, _ := replayFixture(t)
	before := mustReadReport(t, dir)
	if bytes.Contains(before, []byte(`"decision_artifact"`)) || bytes.Contains(before, []byte(`"release_evidence"`)) {
		t.Fatal("fixture unexpectedly contains R6 fields")
	}
	if _, err := LoadPersistedAgentTurn(dir); err != nil {
		t.Fatal(err)
	}
	after := mustReadReport(t, dir)
	if !bytes.Equal(before, after) {
		t.Fatal("legacy replay rewrote the persisted /2 report")
	}
}

// usageLaneForReplay builds a usageLane variant whose recorded lane
// carries package-usage evidence: the persisted fixture report then
// holds the deterministic «affected package/symbol used by product
// code» conditions exactly as a real saved run would.
func usageLaneForReplay(t *testing.T, symbols []string,
	obs []*evidencetools.Observation, extra []VerifiedFact) *LaneResult {
	t.Helper()
	module, pkg := "golang.org/x/net", "golang.org/x/net/http2"
	lane := usageLane(t, module, pkg, symbols, obs,
		append([]VerifiedFact{
			factFor("OBS-0002", "affected-resolve", module+"@v0.10.0 affected"),
		}, extra...))
	lane.SnapshotRoot = t.TempDir()
	return lane
}

// TestReplayPackageUsage_SupportedClosesPath — a persisted /3 run whose
// deterministic lane proved package USE replays into the same L1 ladder:
// the usage condition stays SUPPORTED with the advisory-declared
// usage_subject pinned to the condition, the cited OK PACKAGE_USAGE
// fact's subject matches it, and the recorded agent turn, statuses and
// pins are preserved verbatim. Nothing about the replay consults a
// model.
func TestReplayPackageUsage_SupportedClosesPath(t *testing.T) {
	lane := usageLaneForReplay(t, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2", "",
				"USED", "", evidencetools.CompletenessPartial),
		},
		[]VerifiedFact{
			usageFact("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2", "",
				"TRUE", "", "package golang.org/x/net/http2 used by product source"),
		})
	dir, saved, _ := replayFixtureV3Lane(t, lane, AgentOK)
	// The persisted document really carries the SUPPORTED usage
	// condition — otherwise this test proves nothing.
	var savedUsage *ExploitationCondition
	for i := range saved.ExploitationConditions {
		if saved.ExploitationConditions[i].Subject == subjProductPackageUsage {
			savedUsage = &saved.ExploitationConditions[i]
		}
	}
	if savedUsage == nil || savedUsage.State != StateSupported ||
		savedUsage.UsageSubject == nil ||
		savedUsage.UsageSubject.Package != "golang.org/x/net/http2" {
		t.Fatalf("persisted fixture lacks the SUPPORTED usage condition: %+v", savedUsage)
	}
	if saved.EvidenceLevel == nil || saved.EvidenceLevel.Level != EvidenceLevelL1 {
		t.Fatalf("persisted fixture level = %+v, want L1", saved.EvidenceLevel)
	}

	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("/3 package-usage replay load failed: %v", err)
	}
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "research-replay-pu",
		StartedAt:  time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 10, 6, 9, 1, 0, 0, time.UTC)})
	cs := usageConditions(r)
	if len(cs) != 1 || cs[0].State != StateSupported {
		t.Fatalf("replayed usage conditions = %+v, want one SUPPORTED", cs)
	}
	c := cs[0]
	if c.UsageSubject == nil || c.UsageSubject.Module != "golang.org/x/net" ||
		c.UsageSubject.Package != "golang.org/x/net/http2" || c.UsageSubject.Symbol != "" {
		t.Fatalf("usage_subject not bound to the advisory candidate: %+v", c.UsageSubject)
	}
	// The closing citation is an OK PACKAGE_USAGE fact bound to the
	// same subject — the positive deterministic evidence chain.
	facts := map[string]VerifiedFact{}
	for _, f := range r.VerifiedFacts {
		facts[f.ID] = f
	}
	found := false
	for _, ref := range c.EvidenceRefs {
		if f, ok := facts[ref]; ok &&
			f.Kind == FactKindPackageUsage && f.Status == "OK" &&
			f.UsageSubject != nil &&
			f.UsageSubject.Package == c.UsageSubject.Package {
			found = true
		}
	}
	if !found {
		t.Fatalf("SUPPORTED usage condition cites no matching PACKAGE_USAGE fact: %v", c.EvidenceRefs)
	}
	if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL1 {
		t.Fatalf("replayed level = %+v, want L1", r.EvidenceLevel)
	}
	if r.AgentOutput.Status != saved.AgentOutput.Status ||
		r.AgentOutput.ReplayedFrom == nil {
		t.Fatalf("recorded agent turn not preserved: %+v", r.AgentOutput)
	}
	if r.Run.Harness != (HarnessInfo{}) {
		t.Fatalf("replay produced live harness pins: %+v", r.Run.Harness)
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("replayed package-usage report failed validation:\n%v", err)
	}
}

// TestReplayPackageUsage_RefutedStaysReviewable — a VERIFIED negative
// under a COMPLETE scope replays as REFUTED: the path condition blocks
// L1, the level stays L2, vulnerable_code_reachability is never FALSE,
// and disposition remains REVIEW_REQUIRED/auto_close=false — a refuted
// path is never a safe conclusion.
func TestReplayPackageUsage_RefutedStaysReviewable(t *testing.T) {
	lane := usageLaneForReplay(t, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2", "",
				"NOT_USED", "VERIFIED", evidencetools.CompletenessComplete),
		},
		[]VerifiedFact{
			usageFact("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2", "",
				"FALSE", NegativeVerificationVerified, "no product-source use of golang.org/x/net/http2"),
		})
	dir, saved, _ := replayFixtureV3Lane(t, lane, AgentOK)

	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("/3 refuted-usage replay load failed: %v", err)
	}
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "research-replay-pu-neg",
		StartedAt:  time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 10, 6, 9, 1, 0, 0, time.UTC)})
	cs := usageConditions(r)
	if len(cs) != 1 || cs[0].State != StateRefuted {
		t.Fatalf("replayed usage conditions = %+v, want one REFUTED", cs)
	}
	if r.EvidenceLevel == nil || r.EvidenceLevel.Level != EvidenceLevelL2 {
		t.Fatalf("replayed level = %+v, want L2", r.EvidenceLevel)
	}
	if !containsStr(r.EvidenceLevel.BlockingConditions, cs[0].ID) {
		t.Fatalf("REFUTED usage condition missing from blocking: %v",
			r.EvidenceLevel.BlockingConditions)
	}
	if r.ProductApplicability.VulnerableCodeReachability == "FALSE" {
		t.Fatal("REFUTED package usage downgraded to a safe VCR=FALSE conclusion")
	}
	if r.Disposition.Class != "REVIEW_REQUIRED" || r.Disposition.AutoClose {
		t.Fatalf("REFUTED case left review-required disposition: %+v", r.Disposition)
	}
	// The persisted and replayed refuted rows carry the same state —
	// the replay did not soften or strengthen the recorded negative.
	var savedRefuted bool
	for _, c := range saved.ExploitationConditions {
		if c.Subject == subjProductPackageUsage && c.State == StateRefuted {
			savedRefuted = true
		}
	}
	if !savedRefuted {
		t.Fatal("persisted fixture lost its REFUTED usage condition")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("replayed refuted-usage report failed validation:\n%v", err)
	}
}

// TestReplayPackageUsage_LowerBoundNeverCloses — an UNKNOWN usage
// verdict promotes only to PACKAGE_USAGE_LOWER_BOUND: the condition
// stays UNKNOWN, blocks L1, and no kind=PACKAGE_USAGE carrier fact is
// cited for it — the positive lower bound can never close the path.
func TestReplayPackageUsage_LowerBoundNeverCloses(t *testing.T) {
	lane := usageLaneForReplay(t, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2", "",
				"UNKNOWN", "", evidencetools.CompletenessPartial),
		},
		[]VerifiedFact{
			usageLowerBoundFact("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2",
				"", "package-usage over golang.org/x/net/http2 recorded partial positive content only"),
		})
	dir, _, _ := replayFixtureV3Lane(t, lane, AgentOK)

	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("/3 lower-bound replay load failed: %v", err)
	}
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "research-replay-pu-lb",
		StartedAt:  time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 10, 6, 9, 1, 0, 0, time.UTC)})
	cs := usageConditions(r)
	if len(cs) != 1 || cs[0].State != StateUnknown {
		t.Fatalf("replayed usage conditions = %+v, want one UNKNOWN", cs)
	}
	if r.EvidenceLevel == nil || r.EvidenceLevel.Level == EvidenceLevelL1 {
		t.Fatalf("UNKNOWN usage condition produced L1: %+v", r.EvidenceLevel)
	}
	for _, ref := range cs[0].EvidenceRefs {
		for _, f := range r.VerifiedFacts {
			if f.ID == ref && f.Kind == FactKindPackageUsage {
				t.Fatalf("UNKNOWN usage condition cites a PACKAGE_USAGE carrier fact %s", ref)
			}
		}
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("replayed lower-bound report failed validation:\n%v", err)
	}
}

// TestReplayPackageUsage_TamperedSubjectAborts — rewriting a persisted
// usage condition's usage_subject so it no longer matches the cited
// fact's subject makes the /3 input gate reject the replay: a fact for
// one candidate can never be cited for another, and a tampered saved
// report yields no rebuilt output.
func TestReplayPackageUsage_TamperedSubjectAborts(t *testing.T) {
	lane := usageLaneForReplay(t, nil,
		[]*evidencetools.Observation{
			usageObs("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2", "",
				"USED", "", evidencetools.CompletenessPartial),
		},
		[]VerifiedFact{
			usageFact("OBS-0020", "golang.org/x/net", "golang.org/x/net/http2", "",
				"TRUE", "", "package golang.org/x/net/http2 used by product source"),
		})
	dir, _, _ := replayFixtureV3Lane(t, lane, AgentOK)

	rewriteReport(t, dir, func(r *Report) {
		for i := range r.ExploitationConditions {
			c := &r.ExploitationConditions[i]
			if c.Subject == subjProductPackageUsage && c.UsageSubject != nil {
				c.UsageSubject.Package = "golang.org/x/net/dns"
			}
		}
	})
	if _, err := LoadPersistedAgentTurn(dir); err == nil {
		t.Fatal("replay accepted a usage condition citing a mismatched-subject fact")
	} else if !strings.Contains(err.Error(), "usage_subject") {
		t.Fatalf("replay rejected for an unrelated reason: %v", err)
	}
}

// TestReplayPackageUsage_ModuleOnlyStaysAbsent — a persisted module-only
// advisory replays into a report with no package-usage condition and no
// package-usage fact: the module path is never substituted for a
// package, so the new subject stays ABSENT end to end.
func TestReplayPackageUsage_ModuleOnlyStaysAbsent(t *testing.T) {
	// fakeLane's vuln declares no AffectedPackages — the module-only shape.
	lane := fakeLane(t)
	dir, saved, _ := replayFixtureV3Lane(t, lane, AgentOK)
	for _, c := range saved.ExploitationConditions {
		if c.Subject == subjProductPackageUsage {
			t.Fatalf("module-only fixture carries a usage condition: %+v", c)
		}
	}
	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("/3 module-only replay load failed: %v", err)
	}
	r := Assemble(AssembleInput{Lane: lane, Turn: turn, RunID: "research-replay-pu-mo",
		StartedAt:  time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 10, 6, 9, 1, 0, 0, time.UTC)})
	if cs := usageConditions(r); len(cs) != 0 {
		t.Fatalf("module-only replay gained usage conditions: %+v", cs)
	}
	for _, f := range r.VerifiedFacts {
		if f.Kind == FactKindPackageUsage || f.Kind == FactKindPackageUsageLowerBound {
			t.Fatalf("module-only replay gained a package-usage fact: %+v", f)
		}
	}
	// The recorded gap is carried as a decision-changing unknown, never
	// as a fabricated package subject.
	foundGap := false
	for _, u := range r.Unknowns {
		if strings.Contains(u.Statement, "no package or symbol identifies a package-level subject") {
			foundGap = true
		}
	}
	if !foundGap {
		t.Fatal("module-only replay lost the package-usage gap unknown")
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("replayed module-only report failed validation:\n%v", err)
	}
}

// replayPlanAnswer builds a retained answer carrying a valid verification
// plan bound to the usagescope advisory shape — the same bytes a live
// agent turn would retain.
func replayPlanAnswer() []byte {
	return []byte(`final answer:
{"category":"code_not_reachable",
 "reasoning":"the affected package never links into product code",
 "assessment":{"triage_recommendation":{"action":"needs review"}},
 "verification_plan":{"falsifier":{
   "kind":"package-absent","condition_id":"cond-1",
   "module":"example.com/usagedep","package":"example.com/usagedep/testonly",
   "statement":"the vulnerable package is absent from the product build closure",
   "scope":"paired product/test build closures"},
  "checks":[{"id":"v1","tool":"usage-scope",
    "arguments":{"module":"example.com/usagedep","package":"example.com/usagedep/testonly"},
    "purpose":"classify the declared package in both build closures","condition_id":"cond-1"}]}}`)
}

// TestResearchReplayDecision: a replayed turn preserves the recorded
// verification plan verbatim — the proposal the decision consumes is the
// plan parsed out of the retained answer bytes, identical to what the
// same answer yields through the live extraction path, and no model or
// harness call happens on the replay side.
func TestResearchReplayDecision(t *testing.T) {
	answerText := replayPlanAnswer()
	dir, _ := replayFixture(t)
	// Re-pin the retained answer: the fixture's own answer.txt is replaced
	// with the plan-bearing one and every recorded digest updated.
	ad := filepath.Join(dir, "agent", "attempt-0002")
	newSHA := shaOfBytes(answerText)
	if err := os.WriteFile(filepath.Join(ad, "answer.txt"), answerText, 0o644); err != nil {
		t.Fatal(err)
	}
	repPath := filepath.Join(dir, "report.json")
	rb, err := os.ReadFile(repPath)
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(rb, &rep); err != nil {
		t.Fatal(err)
	}
	upd := func(a *AttemptArtifact) {
		if a != nil {
			a.SHA256 = newSHA
			a.SizeBytes = int64(len(answerText))
		}
	}
	upd(rep.AgentOutput.AnswerArtifact)
	rep.AgentOutput.RawArtifact.SHA256 = &newSHA
	rep.AgentOutput.Reasoning = nil
	if rep.AgentOutput.Extraction != nil {
		upd(rep.AgentOutput.Extraction.AnswerArtifact)
	}
	for i := range rep.Run.Attempts {
		if rep.Run.Attempts[i].Extraction != nil {
			upd(rep.Run.Attempts[i].Extraction.AnswerArtifact)
		}
	}
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repPath, out, 0o644); err != nil {
		t.Fatal(err)
	}

	turn, err := LoadPersistedAgentTurn(dir)
	if err != nil {
		t.Fatalf("replay load: %v", err)
	}
	if turn.Answer == nil || turn.Answer.VerificationPlan == nil {
		t.Fatal("replayed answer lost its verification plan")
	}
	plan := turn.Answer.VerificationPlan
	if plan.Falsifier.ConditionID != "cond-1" || plan.Falsifier.Package != "example.com/usagedep/testonly" ||
		len(plan.Checks) != 1 || plan.Checks[0].Tool != "usage-scope" {
		t.Fatalf("plan=%+v", plan)
	}
	// The retained plan validates like a live one.
	if err := ValidateVerificationPlan(*plan, "", nil); err != nil {
		t.Fatalf("retained plan fails validation: %v", err)
	}
	// Equivalence with the live path: parsing the same raw plan bytes
	// yields the identical proposal the replay feeds VerifyDecision.
	live, lims := ParseVerificationPlan(json.RawMessage(`{"falsifier":{
   "kind":"package-absent","condition_id":"cond-1",
   "module":"example.com/usagedep","package":"example.com/usagedep/testonly",
   "statement":"the vulnerable package is absent from the product build closure",
   "scope":"paired product/test build closures"},
  "checks":[{"id":"v1","tool":"usage-scope",
    "arguments":{"module":"example.com/usagedep","package":"example.com/usagedep/testonly"},
    "purpose":"classify the declared package in both build closures","condition_id":"cond-1"}]}`))
	if len(lims) != 0 || live == nil {
		t.Fatalf("live parse failed: %v", lims)
	}
	lb, _ := json.Marshal(live)
	pb, _ := json.Marshal(plan)
	if string(lb) != string(pb) {
		t.Fatalf("replay plan diverges from live parse:\n%s\nvs\n%s", pb, lb)
	}
	// Decision-input equivalence: the replayed proposal alone carries no
	// authority — with no trace the decision stays INCONCLUSIVE for the
	// trace reason, exactly as a live turn would.
	dec, err := VerifyDecision(t.Context(), DecisionInput{
		Lane:     replayDecisionLane(),
		Proposal: &plan.Falsifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Verdict != domain.VerdictInconclusive || !strings.Contains(dec.Reason, "verification trace") {
		t.Fatalf("decision=%+v", dec)
	}
}

// replayDecisionLane is the lane fixture bound to the replayed plan's
// advisory subject (usagescope's test-only dep package).
func replayDecisionLane() *LaneResult {
	pkg := "example.com/usagedep/testonly"
	return &LaneResult{
		ContentHash: "snapshot-hash",
		Snapshot:    domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"},
		Advisory: AdvisoryRecord{
			Vuln: &domain.Vulnerability{
				Module:           "example.com/usagedep",
				Package:          pkg,
				AffectedPackages: []domain.AffectedPackage{{Path: pkg}},
			},
			Impls: []AffectedImplementation{{ID: "adv-01", Module: "example.com/usagedep", Package: &pkg, Binding: BindExact}},
		},
		Affected: domain.AffectedResult{
			Scope:           exactAdvisoryScope("GO-TEST-0001"),
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
	}
}

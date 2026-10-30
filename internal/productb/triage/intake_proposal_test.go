package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/llm"
	"github.com/fedorovmv/izyan/internal/tracker"
)

// stubIntakeChat is a fake ChatClient returning scripted replies; it records
// the system prompt and transcript so tests can assert the untrusted-data
// contract and that the raw model response is preserved.
type stubIntakeChat struct {
	replies   []string
	finishes  []string
	err       error
	calls     int
	system    string
	sentMsgs  []llm.ChatMessage
	sentTools []llm.ToolDefinition
}

func (s *stubIntakeChat) Chat(_ context.Context, _ llm.ModelRole, system string, msgs []llm.ChatMessage, tools []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	s.calls++
	s.system = system
	s.sentMsgs = append([]llm.ChatMessage(nil), msgs...)
	s.sentTools = tools
	if s.err != nil {
		return llm.ChatMessage{}, "", s.err
	}
	if s.calls > len(s.replies) {
		return llm.ChatMessage{Role: "assistant", Content: s.replies[len(s.replies)-1]}, "stop", nil
	}
	finish := "stop"
	if s.calls <= len(s.finishes) && s.finishes[s.calls-1] != "" {
		finish = s.finishes[s.calls-1]
	}
	return llm.ChatMessage{Role: "assistant", Content: s.replies[s.calls-1]}, finish, nil
}

const intakeTicketText = `Scanner reported CVE-2099-0001 (alias GHSA-xxxx-yyyy-zzzz) in module example.org/library/parser.
Component parser, product Example Service, release 2026.10, built with go1.25.1.
Affected version 1.4.2. Severity: high. Repository https://example.org/repos/example-service.git tag v2026.10.`

func mustIntakeRecord(t *testing.T, text string) RawIntake {
	t.Helper()
	rec, err := ParseIntakeRecord([]byte(text), 1)
	if err != nil {
		t.Fatalf("ParseIntakeRecord: %v", err)
	}
	return rec
}

func TestIntakeProposalExtractValid(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	reply := `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"aliases":["GHSA-xxxx-yyyy-zzzz"],"package":"example.org/library/parser","version":"1.4.2","component":"parser","product":"Example Service","release":"2026.10","go_version":"go1.25.1","severity":"high","summary":"parser overflow","source_hints":["example-service"],"ref_hint":"v2026.10"}`
	chat := &stubIntakeChat{replies: []string{"Sure, here is the extraction:\n```json\n" + reply + "\n```"}}

	proposal, transcript, err := ExtractIntakeProposal(context.Background(), chat, raw)
	if err != nil {
		t.Fatalf("ExtractIntakeProposal: %v", err)
	}
	if proposal.SchemaVersion != IntakeProposalSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", proposal.SchemaVersion, IntakeProposalSchemaVersion)
	}
	if len(proposal.VulnerabilityIDs) != 1 || proposal.VulnerabilityIDs[0] != "CVE-2099-0001" {
		t.Fatalf("vulnerability_ids = %v", proposal.VulnerabilityIDs)
	}
	if proposal.Package != "example.org/library/parser" || proposal.Version != "1.4.2" {
		t.Fatalf("package/version = %q/%q", proposal.Package, proposal.Version)
	}
	if proposal.Severity != "high" {
		t.Fatalf("severity = %q", proposal.Severity)
	}
	// The transcript must preserve the user data message and the verbatim
	// raw model response (fences included) for audit/replay.
	if len(transcript) != 2 {
		t.Fatalf("transcript len = %d, want 2", len(transcript))
	}
	if transcript[0].Role != "user" || !strings.Contains(transcript[0].Content, "CVE-2099-0001") {
		t.Fatalf("data message missing raw document: %q", transcript[0].Content)
	}
	if transcript[1].Role != "assistant" || !strings.Contains(transcript[1].Content, "```json") {
		t.Fatalf("raw model response not preserved verbatim: %q", transcript[1].Content)
	}
	if chat.calls != 1 {
		t.Fatalf("chat calls = %d, want 1", chat.calls)
	}
}

func TestIntakeProposalExtractEmptyInput(t *testing.T) {
	chat := &stubIntakeChat{replies: []string{"{}"}}
	if _, _, err := ExtractIntakeProposal(context.Background(), chat, RawIntake{}); err == nil {
		t.Fatal("expected error for empty intake record")
	}
	if chat.calls != 0 {
		t.Fatalf("chat must not be called for empty input, calls = %d", chat.calls)
	}
}

func TestIntakeProposalExtractNilClient(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	if _, _, err := ExtractIntakeProposal(context.Background(), nil, raw); err == nil {
		t.Fatal("expected error for nil chat client")
	}
}

func TestIntakeProposalExtractNonJSON(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	chat := &stubIntakeChat{replies: []string{"no json here at all"}}
	if _, _, err := ExtractIntakeProposal(context.Background(), chat, raw); err == nil {
		t.Fatal("expected error for non-JSON model output")
	}
}

func TestIntakeProposalExtractRefusal(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	chat := &stubIntakeChat{replies: []string{""}, finishes: []string{"content_filter"}}
	if _, _, err := ExtractIntakeProposal(context.Background(), chat, raw); err == nil {
		t.Fatal("expected error for provider refusal")
	}
}

func TestIntakeProposalExtractForeignSchema(t *testing.T) {
	raw := mustIntakeRecord(t, intakeTicketText)
	chat := &stubIntakeChat{replies: []string{`{"schema_version":"ticket.v1","vulnerability":"CVE-2099-0001"}`}}
	if _, _, err := ExtractIntakeProposal(context.Background(), chat, raw); err == nil {
		t.Fatal("expected error for a foreign schema_version")
	}
}

// The extractor prompt must mark the document as untrusted data, pin the
// intake-proposal.v1 shape, and forbid inventing fields; the document itself
// must never enter the system prompt.
func TestIntakeProposalPromptContract(t *testing.T) {
	system := BuildIntakePrompt()
	for _, want := range []string{"UNTRUSTED", "intake-proposal.v1", "extract", "severity"} {
		if !strings.Contains(system, want) {
			t.Fatalf("system prompt missing %q:\n%s", want, system)
		}
	}
	if strings.Contains(system, "CVE-2099-0001") {
		t.Fatal("system prompt must not embed document content")
	}
	raw := mustIntakeRecord(t, intakeTicketText)
	data := BuildIntakeDataMessage(raw)
	if !strings.Contains(data, "UNTRUSTED") || !strings.Contains(data, string(raw.Raw)) {
		t.Fatalf("data message must carry the raw document marked untrusted: %q", data)
	}
}

// The generic schema has no tracker fields: even when a tracker-shaped
// document is the source material and the model echoes tracker keys back,
// the serialized proposal can only carry domain fields.
func TestIntakeProposalDropsTrackerFields(t *testing.T) {
	trackerDoc := `{"key":"ISSUE-0001","status":"Open","assignee":"user-example","comment":"please triage","summary":"CVE-2099-0001 in parser","severity":"high"}`
	raw := mustIntakeRecord(t, trackerDoc)
	reply := `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"package":"example.org/library/parser","summary":"parser issue","ticket_id":"ISSUE-0001","status":"Open","assignee":"user-example","comment":"please triage"}`
	chat := &stubIntakeChat{replies: []string{reply}}

	proposal, _, err := ExtractIntakeProposal(context.Background(), chat, raw)
	if err != nil {
		t.Fatalf("ExtractIntakeProposal: %v", err)
	}
	data, err := json.Marshal(proposal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, banned := range []string{"ticket_id", "ticket_key", "key", "status", "assignee", "comment", "comments", "workflow", "transition", "priority", "recommendation", "source_id", "ref"} {
		if _, ok := keys[banned]; ok {
			t.Fatalf("proposal carries tracker-only key %q: %s", banned, data)
		}
	}
	for k := range keys {
		switch k {
		case "schema_version", "vulnerability_ids", "aliases", "package", "version",
			"component", "product", "release", "go_version", "severity", "summary",
			"source_hints", "ref_hint":
		default:
			t.Fatalf("unexpected key %q in serialized proposal: %s", k, data)
		}
	}
}

// Adapter coverage: legacy tracker LLM extraction may feed source material,
// but its tracker fields (Ticket.ID etc.) have no representation in
// IntakeProposal — the domain schema discards workflow data by construction.
func TestIntakeProposalTrackerAdapterIsolation(t *testing.T) {
	completer := trackerCompleter{reply: `{"vulnerability":"CVE-2099-0001","ticket_id":"ISSUE-0001","package":"example.org/library/parser","summary":"parser issue"}`}
	tk, err := tracker.ExtractTicketWithLLM(context.Background(), completer, "ISSUE-0001: CVE-2099-0001 in example.org/library/parser")
	if err != nil {
		t.Fatalf("ExtractTicketWithLLM: %v", err)
	}
	if tk.ID != "ISSUE-0001" {
		t.Fatalf("tracker adapter keeps its ticket id, got %q", tk.ID)
	}
	proposal := IntakeProposal{SchemaVersion: IntakeProposalSchemaVersion}
	data, _ := json.Marshal(proposal)
	if strings.Contains(string(data), "ISSUE-0001") || strings.Contains(string(data), "ticket") {
		t.Fatalf("proposal must not carry tracker fields: %s", data)
	}
}

type trackerCompleter struct{ reply string }

func (c trackerCompleter) Complete(_ context.Context, _, _ string) (string, error) {
	return c.reply, nil
}

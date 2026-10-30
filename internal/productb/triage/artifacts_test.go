package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/llm"
)

func artifactClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
}

func inputForID(t *testing.T, id string) FindingInput {
	t.Helper()
	raw, err := json.Marshal(Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     id,
		Vulnerability: Vulnerability{IDs: []string{"CVE-2025-1234"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var f Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return FindingInput{Finding: f, Raw: raw, SHA256: sha256Hex(t, raw)}
}

func writeFixture(t *testing.T) (FindingInput, SnapshotManifest, AgentRun, Assessment) {
	t.Helper()
	in := inputForID(t, "scanner-123")
	manifest := SnapshotManifest{
		SchemaVersion: SnapshotSchemaVersion,
		FindingID:     in.Finding.FindingID,
		Repository:    t.TempDir(),
		ContentHash:   "deadbeef",
		InputHash:     in.SHA256,
		Files:         []SnapshotFile{{Path: "main.go", SHA256: "ab12", Size: 7}},
	}
	assessment := Assessment{
		SchemaVersion:  AssessmentSchemaVersion,
		FindingID:      in.Finding.FindingID,
		Verdict:        VerdictNotExploitable,
		VerdictSubtype: "not_affected",
		Summary:        "vulnerable code path is absent",
		FactValidation: ValidationComplete,
		FactValidationDetail: &FactValidation{
			Status:     ValidationComplete,
			References: []ReferenceCheck{{EvidenceID: "e1", Status: FactValid, Locator: "main.go:1-2"}},
		},
		Claims: []Claim{
			{
				ID:               "c1",
				Statement:        "parser is not linked",
				Basis:            PremiseInterpreted,
				Subject:          "parser linkage",
				Scope:            "captured snapshot",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"e1"},
			},
		},
		Evidence: []EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go:1-2", Quote: "package main"}},
		Unknowns: []Unknown{{ID: "u1", Description: "runtime config not captured"}},
		ProposedAction: HumanAction{
			Kind:             HumanActionClose,
			Instruction:      "close as not exploitable",
			Rationale:        "the parser is not linked into the captured build",
			Scope:            "captured snapshot",
			DecisiveClaimIDs: []string{"c1"},
			ReconsiderWhen:   []string{"a build that links the parser is captured"},
		},
	}
	run := AgentRun{
		Assessment:   assessment,
		RawMessages:  []llm.ChatMessage{{Role: "user", Content: "prompt"}, {Role: "assistant", Content: "raw model reply"}},
		PromptHash:   "prompt-hash",
		ResponseHash: "response-hash",
		Steps:        2,
		ToolCalls:    1,
	}
	return in, manifest, run, assessment
}

func TestArtifactWriterCreatesAllArtifacts(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock(), Model: "test-model", ToolVersions: map[string]string{"tools": "v1"}}

	art, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	wantRoot := filepath.Join(out, "scanner-123")
	for name, got := range map[string]string{
		"InputPath":      art.InputPath,
		"SnapshotPath":   art.SnapshotPath,
		"RawAgentPath":   art.RawAgentPath,
		"AssessmentPath": art.AssessmentPath,
		"MarkdownPath":   art.MarkdownPath,
		"AuditPath":      art.AuditPath,
	} {
		want := filepath.Join(wantRoot, map[string]string{
			"InputPath":      "input.json",
			"SnapshotPath":   "snapshot.json",
			"RawAgentPath":   "raw-agent.json",
			"AssessmentPath": "assessment.json",
			"MarkdownPath":   "assessment.md",
			"AuditPath":      filepath.Join("audit", "events.jsonl"),
		}[name])
		if got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
		if info, err := os.Stat(got); err != nil || info.IsDir() {
			t.Fatalf("%s missing on disk: %v", got, err)
		}
	}
	if art.RootDir != wantRoot || art.RunID == "" {
		t.Fatalf("RootDir=%q RunID=%q", art.RootDir, art.RunID)
	}

	// input.json preserves the original record bytes verbatim.
	inputBytes, err := os.ReadFile(art.InputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inputBytes, in.Raw) {
		t.Fatalf("input.json = %s, want raw input %s", inputBytes, in.Raw)
	}

	data, err := os.ReadFile(art.AssessmentPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc Assessment
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("assessment.json: %v", err)
	}
	if doc.SchemaVersion != AssessmentSchemaVersion || doc.FindingID != in.Finding.FindingID {
		t.Fatalf("identity: %+v", doc)
	}
	if doc.Verdict != VerdictNotExploitable || doc.VerdictSource != "agent" {
		t.Fatalf("verdict=%q source=%q", doc.Verdict, doc.VerdictSource)
	}
	if doc.FactValidation != ValidationComplete {
		t.Fatalf("validation=%q", doc.FactValidation)
	}
	// The CI policy outcome is not an assessment field any more: it belongs
	// to the decision package's machine disposition.
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"automation", "automation_reason"} {
		if _, ok := wire[key]; ok {
			t.Fatalf("assessment.json must not carry %q", key)
		}
	}
	if len(doc.Claims) != 1 || len(doc.Evidence) != 1 || len(doc.Unknowns) != 1 {
		t.Fatalf("claims/evidence/unknowns lost: %+v", doc)
	}
	if doc.FactValidationDetail == nil || len(doc.FactValidationDetail.References) != 1 ||
		doc.FactValidationDetail.References[0].Status != FactValid {
		t.Fatalf("fact_validation_detail lost: %+v", doc.FactValidationDetail)
	}
	if doc.Audit == nil {
		t.Fatal("audit block missing")
	}
	if doc.Audit.FindingHash != in.SHA256 || doc.Audit.SnapshotHash != manifest.ContentHash {
		t.Fatalf("hashes: %+v", doc.Audit)
	}
	if doc.Audit.PromptHash != run.PromptHash || doc.Audit.ResponseHash != run.ResponseHash {
		t.Fatalf("run hashes: %+v", doc.Audit)
	}
	if doc.Audit.Model != "test-model" || doc.Audit.ToolVersions["tools"] != "v1" {
		t.Fatalf("tool/model metadata: %+v", doc.Audit)
	}
	// assessment_hash covers the canonical document without the hash field.
	if doc.Audit.AssessmentHash == "" {
		t.Fatal("assessment_hash is empty")
	}
	verify := doc
	auditCopy := *doc.Audit
	auditCopy.AssessmentHash = ""
	verify.Audit = &auditCopy
	canon, err := json.Marshal(verify)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Audit.AssessmentHash != sha256Hex(t, canon) {
		t.Fatalf("assessment_hash does not cover canonical assessment")
	}

	rawData, err := os.ReadFile(art.RawAgentPath)
	if err != nil {
		t.Fatal(err)
	}
	var rawDoc struct {
		SchemaVersion string            `json:"schema_version"`
		RunID         string            `json:"run_id"`
		FindingID     string            `json:"finding_id"`
		PromptHash    string            `json:"prompt_hash"`
		ResponseHash  string            `json:"response_hash"`
		Steps         int               `json:"steps"`
		ToolCalls     int               `json:"tool_calls"`
		Messages      []llm.ChatMessage `json:"messages"`
	}
	if err := json.Unmarshal(rawData, &rawDoc); err != nil {
		t.Fatalf("raw-agent.json: %v", err)
	}
	if rawDoc.RunID != art.RunID || rawDoc.FindingID != in.Finding.FindingID {
		t.Fatalf("raw doc identity: %+v", rawDoc)
	}
	if rawDoc.PromptHash != run.PromptHash || rawDoc.ResponseHash != run.ResponseHash {
		t.Fatalf("raw doc hashes: %+v", rawDoc)
	}
	if len(rawDoc.Messages) != 2 || rawDoc.Messages[1].Content != "raw model reply" {
		t.Fatalf("raw transcript lost: %+v", rawDoc.Messages)
	}

	md, err := os.ReadFile(art.MarkdownPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(md)
	for _, want := range []string{
		"NOT_EXPLOITABLE", "COMPLETE", "ALLOW",
		"vulnerable code path is absent",
		"parser is not linked", "e1", "main.go:1-2",
		"runtime config not captured",
		"semantic correctness", "audit/events.jsonl",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("assessment.md missing %q:\n%s", want, text)
		}
	}
}

// TestArtifactWriterStdoutSummary: the investigation write never announces
// the primary result. Only a successful decision write prints the one human
// summary line — finding, proposed action, derived support, machine
// disposition and the decision.md path.
func TestArtifactWriterStdoutSummary(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock(), Stdout: &buf}
	art, err := w.Write(ctx, out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("Write announced a primary result before the action package existed: %q", buf.String())
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
	if err := w.WriteDecision(ctx, out, pkg); err != nil {
		t.Fatalf("WriteDecision: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("a successful decision write printed no primary result")
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("the primary result is not one concise line: %q", line)
	}
	for _, want := range []string{
		pkg.FindingID,
		"action=" + string(pkg.ProposedAction.Kind),
		"support=" + string(pkg.Support.Level),
		"machine=" + string(pkg.MachineDisposition.Recommendation),
		"decision=" + art.DecisionMarkdownPath,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("summary missing %q: %q", want, line)
		}
	}
	for _, unwanted := range []string{"assessment=", "verdict=", "fact_validation="} {
		if strings.Contains(line, unwanted) {
			t.Fatalf("summary still presents the investigation artifact as the result (%q): %q", unwanted, line)
		}
	}
}

func TestArtifactWriterForeignDirRejected(t *testing.T) {
	out := t.TempDir()
	_, manifest, run, assessment := writeFixture(t)
	forID := func(id string) Assessment {
		a := assessment
		a.FindingID = id
		return a
	}
	inA := inputForID(t, "scanner_123")
	w := ArtifactWriter{Clock: artifactClock()}
	artA, err := w.Write(context.Background(), out, inA, manifest, run, forID("scanner_123"), nil, nil)
	if err != nil {
		t.Fatalf("Write A: %v", err)
	}
	before, err := os.ReadFile(artA.AssessmentPath)
	if err != nil {
		t.Fatal(err)
	}

	// "scanner/123" percent-encodes to "scanner%2f123", disjoint from
	// "scanner_123": the run succeeds in its own directory without
	// touching the foreign one.
	inB := inputForID(t, "scanner/123")
	artB, err := w.Write(context.Background(), out, inB, manifest, run, forID("scanner/123"), nil, nil)
	if err != nil {
		t.Fatalf("Write B into its own directory: %v", err)
	}
	if artB.RootDir == artA.RootDir {
		t.Fatal("distinct findings share a run directory")
	}
	after, err := os.ReadFile(artA.AssessmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("assessment.json of another finding was overwritten")
	}

	// Unrelated finding gets its own directory and both survive.
	inC := inputForID(t, "scanner-456")
	artC, err := w.Write(context.Background(), out, inC, manifest, run, forID("scanner-456"), nil, nil)
	if err != nil {
		t.Fatalf("Write C: %v", err)
	}
	if artC.RootDir == artA.RootDir {
		t.Fatal("distinct findings share a run directory")
	}
	if _, err := os.Stat(artC.AssessmentPath); err != nil {
		t.Fatalf("second run artifacts missing: %v", err)
	}
	if !bytes.Equal(mustRead(t, artA.AssessmentPath), before) {
		t.Fatal("first run artifacts were modified by a later run")
	}
}

// TestArtifactWriterRejectsForeignAssessment covers the identity contract:
// an assessment bound to a different (or no) finding_id is a technical
// error, never silently re-labelled with the input's id.
func TestArtifactWriterRejectsForeignAssessment(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}

	for _, tc := range []struct {
		name      string
		findingID string
	}{
		{name: "other finding", findingID: "scanner-999"},
		{name: "empty finding_id", findingID: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := assessment
			a.FindingID = tc.findingID
			if _, err := w.Write(context.Background(), out, in, manifest, run, a, nil, nil); err == nil {
				t.Fatalf("Write accepted finding_id %q for input %q", tc.findingID, in.Finding.FindingID)
			}
		})
	}
}

func TestArtifactWriterRerunSameFinding(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}
	first, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	assessment.Verdict = VerdictInconclusive
	second, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write 2: %v", err)
	}
	if first.RootDir != second.RootDir {
		t.Fatal("same finding moved to a different directory")
	}
	data, err := os.ReadFile(second.AssessmentPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc Assessment
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Verdict != VerdictInconclusive {
		t.Fatalf("rerun did not refresh assessment.json: %q", doc.Verdict)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAtomicOutputFailureLeavesNoFile(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	// An existing directory at the final name makes the rename of the
	// fully written temp file fail on POSIX.
	if err := os.MkdirAll(filepath.Join(out, "scanner-123", "assessment.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := ArtifactWriter{Clock: artifactClock()}
	_, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err == nil {
		t.Fatal("expected write error")
	}
	// The final name was never replaced by a partial file.
	info, statErr := os.Stat(filepath.Join(out, "scanner-123", "assessment.json"))
	if statErr != nil || !info.IsDir() {
		t.Fatalf("assessment.json was clobbered: info=%v err=%v", info, statErr)
	}
	// No temp files remain under the run directory.
	var leftovers []string
	filepath.Walk(filepath.Join(out, "scanner-123"), func(path string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() && strings.Contains(fi.Name(), ".tmp") {
			leftovers = append(leftovers, path)
		}
		return nil
	})
	if len(leftovers) > 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
	// A subsequent run recovers once the conflicting directory is removed.
	if err := os.Remove(filepath.Join(out, "scanner-123", "assessment.json")); err != nil {
		t.Fatal(err)
	}
	art, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("recovery write: %v", err)
	}
	if _, err := os.Stat(art.AssessmentPath); err != nil {
		t.Fatalf("assessment.json missing after recovery: %v", err)
	}
}

// TestFactValidationDetailPersisted covers the fact-gate audit trail:
// per-reference status/locator/reason and gate limitations land in
// assessment.json as fact_validation_detail and render in assessment.md.
func TestFactValidationDetailPersisted(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	assessment.FactValidation = ValidationPartial
	assessment.FactValidationDetail = &FactValidation{
		Status: ValidationPartial,
		References: []ReferenceCheck{
			{EvidenceID: "e1", Status: FactValid, Locator: "main.go:1-2"},
			{Status: FactUnreferenced, Reason: `decision-relevant claim "c2" cites no evidence`},
		},
		Limitations: []string{"no sbom declared for the finding"},
	}
	w := ArtifactWriter{Clock: artifactClock()}

	art, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc Assessment
	if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &doc); err != nil {
		t.Fatalf("assessment.json: %v", err)
	}
	d := doc.FactValidationDetail
	if d == nil {
		t.Fatal("assessment.json has no fact_validation_detail")
	}
	if d.Status != ValidationPartial || len(d.References) != 2 {
		t.Fatalf("fact_validation_detail = %+v", d)
	}
	if d.References[1].Status != FactUnreferenced || d.References[1].Reason == "" {
		t.Fatalf("unreferenced check lost: %+v", d.References[1])
	}
	if len(d.Limitations) != 1 {
		t.Fatalf("limitations lost: %+v", d)
	}

	md := string(mustRead(t, art.MarkdownPath))
	for _, want := range []string{
		"Fact validation detail",
		"e1", "VALID", "main.go:1-2",
		"UNREFERENCED", "cites no evidence",
		"no sbom declared for the finding",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("assessment.md missing %q:\n%s", want, md)
		}
	}
}

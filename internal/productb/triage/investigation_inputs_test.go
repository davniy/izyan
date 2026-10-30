package triage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/llm"
)

func investigationFile(t *testing.T, dir, name string, data []byte) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, hashBytes(data)
}

func writeInvestigationManifest(t *testing.T, dir string, manifest map[string]any) string {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "investigation-inputs.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func recordManifestEntry(recordID string, aliases []string, path, sha string, size *int64) map[string]any {
	entry := map[string]any{"record_id": recordID, "path": path, "sha256": sha, "source": "operator-freeze"}
	if len(aliases) > 0 {
		entry["aliases"] = aliases
	}
	if size != nil {
		entry["size"] = *size
	}
	return entry
}

// TestInvestigationInputsRejectForeignOrChangedMaterial pins the strict
// manifest contract: identity collisions, digest/size drift, foreign fix
// ownership and path escapes all fail before any agent work.
func TestInvestigationInputsRejectForeignOrChangedMaterial(t *testing.T) {
	base := t.TempDir()
	recordA := []byte(`{"id":"CVE-2026-0001","summary":"first captured advisory"}`)
	recordB := []byte(`{"id":"CVE-2026-0002","summary":"second captured advisory"}`)
	fixA := []byte("--- a/one.go\n+++ b/one.go\n")
	_, shaA := investigationFile(t, base, "a.json", recordA)
	_, shaB := investigationFile(t, base, "b.json", recordB)
	_, shaFix := investigationFile(t, base, "fix.diff", fixA)

	valid := func() map[string]any {
		sizeA := int64(len(recordA))
		return map[string]any{
			"schema_version": InvestigationInputsSchemaVersion,
			"records": []any{
				recordManifestEntry("CVE-2026-0001", []string{"GHSA-aaaa-0000-0001"}, "a.json", shaA, &sizeA),
				recordManifestEntry("CVE-2026-0002", []string{"GHSA-bbbb-0000-0002"}, "b.json", shaB, nil),
			},
			"fixes": []any{map[string]any{
				"record_id": "CVE-2026-0001", "record_sha256": shaA,
				"locator": "https://example.test/fix/one.diff", "outcome": "captured",
				"path": "fix.diff", "sha256": shaFix,
			}},
		}
	}
	loadValid := func() InvestigationInputs {
		t.Helper()
		in, err := LoadInvestigationInputs(writeInvestigationManifest(t, base, valid()))
		if err != nil {
			t.Fatalf("baseline manifest: %v", err)
		}
		return in
	}
	baseline := loadValid()
	if len(baseline.Records) != 2 || len(baseline.Fixes) != 1 {
		t.Fatalf("baseline captured set = records %d fixes %d", len(baseline.Records), len(baseline.Fixes))
	}
	if baseline.Records[0].RecordID != "CVE-2026-0001" || baseline.Records[0].Aliases[0] != "GHSA-aaaa-0000-0001" {
		t.Fatalf("baseline identity = %+v", baseline.Records[0])
	}

	cases := []struct {
		name    string
		edit    func(map[string]any)
		wantSub string
	}{
		{
			name: "duplicate identities with different bytes",
			edit: func(m map[string]any) {
				m["records"] = append(m["records"].([]any),
					recordManifestEntry("CVE-2026-0001", nil, "b.json", shaB, nil))
			},
			wantSub: "duplicate identity",
		},
		{
			name: "wrong digest",
			edit: func(m map[string]any) {
				m["records"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			},
			wantSub: "does not match declared",
		},
		{
			name: "wrong size",
			edit: func(m map[string]any) {
				size := int64(len(recordA) + 1)
				m["records"].([]any)[0].(map[string]any)["size"] = size
			},
			wantSub: "size",
		},
		{
			name: "undeclared fix ownership",
			edit: func(m map[string]any) {
				m["fixes"].([]any)[0].(map[string]any)["record_id"] = "CVE-2026-9999"
			},
			wantSub: "undeclared owning record",
		},
		{
			name: "foreign fix digest",
			edit: func(m map[string]any) {
				m["fixes"].([]any)[0].(map[string]any)["record_sha256"] = shaB
			},
			wantSub: "owning record digest",
		},
		{
			name: "traversal",
			edit: func(m map[string]any) {
				m["records"].([]any)[0].(map[string]any)["path"] = "../outside.json"
			},
			wantSub: "escapes the manifest directory",
		},
		{
			name: "absolute path",
			edit: func(m map[string]any) {
				abs, _ := filepath.Abs(filepath.Join(base, "a.json"))
				m["records"].([]any)[0].(map[string]any)["path"] = abs
			},
			wantSub: "absolute",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := valid()
			tc.edit(m)
			_, err := LoadInvestigationInputs(writeInvestigationManifest(t, base, m))
			if err == nil {
				t.Fatalf("%s: manifest loaded cleanly, want rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: error %q does not name %q", tc.name, err, tc.wantSub)
			}
		})
	}

	t.Run("symlink escape", func(t *testing.T) {
		outside := t.TempDir()
		outsidePath := filepath.Join(outside, "secret.json")
		if err := os.WriteFile(outsidePath, []byte(`{"id":"CVE-2026-7777"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "escape.json")
		if err := os.Symlink(outsidePath, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		m := valid()
		m["records"].([]any)[0].(map[string]any)["path"] = "escape.json"
		m["records"].([]any)[0].(map[string]any)["sha256"] = hashBytes([]byte(`{"id":"CVE-2026-7777"}`))
		_, err := LoadInvestigationInputs(writeInvestigationManifest(t, base, m))
		if err == nil || !strings.Contains(err.Error(), "symlink escape") {
			t.Fatalf("symlink escape: err = %v, want a symlink-escape rejection", err)
		}
	})
}

// TestReadMaterialReturnsCapturedBytes: read_material serves exact bounded
// byte slices of captured material, resolves aliases only inside the
// captured set, and records an unavailable outcome instead of fetching.
func TestReadMaterialReturnsCapturedBytes(t *testing.T) {
	recordRaw := []byte("advisory-bytes:0123456789abcdef")
	fixRaw := []byte("--- patch one ---\n--- patch two ---\n")
	recordSHA := hashBytes(recordRaw)
	fixSHA := hashBytes(fixRaw)
	inv := InvestigationInputs{
		Records: []CapturedRecord{{
			RecordID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-0000-0001"},
			SHA256: recordSHA, Size: int64(len(recordRaw)), Source: "operator-freeze", Raw: recordRaw,
		}},
		Fixes: []CapturedFix{
			{RecordID: "CVE-2026-0001", RecordSHA256: recordSHA, Locator: "https://example.test/fix/one.diff",
				Outcome: CapturedFixCaptured, SHA256: fixSHA, Size: int64(len(fixRaw)), Raw: fixRaw},
			{RecordID: "CVE-2026-0001", RecordSHA256: recordSHA, Locator: "https://example.test/fix/missing.diff",
				Outcome: CapturedFixMissing},
		},
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("captured fixture: %v", err)
	}
	rt := ReadOnlyTools{Investigation: inv}

	obs := callTool(t, &rt, context.Background(), "read_material", map[string]any{
		"material_id": "record:CVE-2026-0001", "offset": 6, "max_bytes": 8,
	})
	if obs.Status != ToolStatusOK {
		t.Fatalf("record read status = %q (%v)", obs.Status, obs.Limitations)
	}
	data := obsData(t, obs)
	if got := data["content"]; got != string(recordRaw[6:14]) {
		t.Fatalf("record slice = %q, want %q", got, string(recordRaw[6:14]))
	}
	if got := int64(data["next_offset"].(float64)); got != 14 {
		t.Fatalf("next_offset = %d, want 14", got)
	}
	if data["eof"].(bool) {
		t.Fatal("first bounded slice claims eof before the record ends")
	}
	if got := data["sha256"]; got != recordSHA {
		t.Fatalf("sha256 = %v, want %s", got, recordSHA)
	}

	// An explicit alias resolves inside the captured set.
	obs = callTool(t, &rt, context.Background(), "read_material", map[string]any{
		"material_id": "GHSA-aaaa-0000-0001", "max_bytes": 9,
	})
	if obs.Status != ToolStatusOK || obsData(t, obs)["content"] != string(recordRaw[:9]) {
		t.Fatalf("alias read = %+v", obs)
	}

	// A fix reads back by exact locator and by its material id.
	for _, id := range []string{"https://example.test/fix/one.diff", CapturedFixMaterialID("CVE-2026-0001", "https://example.test/fix/one.diff")} {
		obs = callTool(t, &rt, context.Background(), "read_material", map[string]any{"material_id": id})
		if obs.Status != ToolStatusOK {
			t.Fatalf("fix read %q status = %q", id, obs.Status)
		}
		if obsData(t, obs)["content"] != string(fixRaw) {
			t.Fatalf("fix read %q content mismatch", id)
		}
	}

	// Offset past the end is an empty slice with eof=true, never an error.
	obs = callTool(t, &rt, context.Background(), "read_material", map[string]any{
		"material_id": "record:CVE-2026-0001", "offset": 10000,
	})
	if obs.Status != ToolStatusOK || obsData(t, obs)["eof"] != true || obsData(t, obs)["returned_bytes"].(float64) != 0 {
		t.Fatalf("past-end read = %+v", obs)
	}

	// A missing fix records its outcome; it never invents bytes.
	obs = callTool(t, &rt, context.Background(), "read_material", map[string]any{
		"material_id": "https://example.test/fix/missing.diff",
	})
	if obs.Status != ToolStatusUnavailable {
		t.Fatalf("missing fix status = %q, want UNAVAILABLE", obs.Status)
	}
	if !hasLimitation(obs, "recorded as missing") {
		t.Fatalf("missing fix limitations = %v", obs.Limitations)
	}

	// Unknown ids are unavailable; aliases never escape the captured set.
	obs = callTool(t, &rt, context.Background(), "read_material", map[string]any{
		"material_id": "GHSA-ffff-0000-9999",
	})
	if obs.Status != ToolStatusUnavailable || !hasLimitation(obs, "not in the captured investigation set") {
		t.Fatalf("unknown material = %+v", obs)
	}
}

// capturedChat records the first request surface and scripts two
// read_material calls followed by a final assessment.
type capturedChat struct {
	t         *testing.T
	system    string
	messages  []llm.ChatMessage
	defs      []llm.ToolDefinition
	responses []llm.ChatMessage
	calls     int
}

func (c *capturedChat) Chat(_ context.Context, _ llm.ModelRole, system string, messages []llm.ChatMessage, defs []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	if c.calls == 0 {
		c.system, c.messages, c.defs = system, append([]llm.ChatMessage(nil), messages...), defs
	}
	c.calls++
	if c.calls-1 >= len(c.responses) {
		return llm.ChatMessage{Role: "assistant", Content: validAssessment()}, "stop", nil
	}
	return c.responses[c.calls-1], "stop", nil
}

// TestAgentReceivesCapturedAdvisoryAndFixSet proves the scripted agent sees
// the supplied record/fix identities in its data message and can read both
// exact byte sets (two records, two locators) through read_material.
func TestAgentReceivesCapturedAdvisoryAndFixSet(t *testing.T) {
	recordA := []byte(`{"id":"CVE-2026-0001","summary":"first captured advisory","aliases":["GHSA-aaaa-0000-0001"]}`)
	recordB := []byte(`{"id":"CVE-2026-0002","summary":"second captured advisory"}`)
	fixA := []byte("--- a/one.go\n+++ b/one.go\n+fixed\n")
	fixB := []byte("--- a/two.go\n+++ b/two.go\n+also fixed\n")
	inv := InvestigationInputs{
		Records: []CapturedRecord{
			{RecordID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-0000-0001"}, SHA256: hashBytes(recordA), Size: int64(len(recordA)), Source: "operator-freeze", Raw: recordA},
			{RecordID: "CVE-2026-0002", SHA256: hashBytes(recordB), Size: int64(len(recordB)), Source: "operator-freeze", Partial: true, Raw: recordB},
		},
		Fixes: []CapturedFix{
			{RecordID: "CVE-2026-0001", RecordSHA256: hashBytes(recordA), Locator: "https://example.test/fix/one.diff", Outcome: CapturedFixCaptured, SHA256: hashBytes(fixA), Size: int64(len(fixA)), Raw: fixA},
			{RecordID: "CVE-2026-0002", RecordSHA256: hashBytes(recordB), Locator: "https://example.test/fix/two.diff", Outcome: CapturedFixCaptured, SHA256: hashBytes(fixB), Size: int64(len(fixB)), Raw: fixB},
		},
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("captured fixture: %v", err)
	}
	materialIDRecordB := CapturedRecordMaterialID("CVE-2026-0002")
	materialIDFixA := CapturedFixMaterialID("CVE-2026-0001", "https://example.test/fix/one.diff")
	client := &capturedChat{
		t: t,
		responses: []llm.ChatMessage{
			{Role: "assistant", ToolCalls: []llm.ToolCall{
				{ID: "c1", Type: "function", Function: llm.FunctionCall{Name: "read_material", Arguments: `{"material_id":"` + materialIDRecordB + `"}`}},
				{ID: "c2", Type: "function", Function: llm.FunctionCall{Name: "read_material", Arguments: `{"material_id":"` + materialIDFixA + `"}`}},
			}},
			{Role: "assistant", Content: validAssessment()},
		},
	}
	in := FindingInput{Finding: Finding{SchemaVersion: FindingSchemaVersion, FindingID: "f", Vulnerability: Vulnerability{IDs: []string{"CVE-2026-0001"}}}}
	obsStore := NewRunObservationStore("run-1", 1)
	tools := &ReadOnlyTools{Finding: in, Investigation: inv, ObservationStore: obsStore}
	run, err := AgentRunner{
		Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 4},
		Materials: BuildAgentMaterials(MaterialSet{}, inv),
	}.Run(context.Background(), in, SnapshotManifest{SchemaVersion: SnapshotSchemaVersion, FindingID: "f"})
	if err != nil {
		t.Fatalf("agent run: %v", err)
	}
	if run.Assessment.Verdict != VerdictInconclusive || len(client.defs) == 0 {
		t.Fatalf("agent run did not reach the scripted assessment: %+v", run.Assessment)
	}
	dataMsg := client.messages[0].Content
	for _, want := range []string{
		"CVE-2026-0001", "GHSA-aaaa-0000-0001", "CVE-2026-0002",
		"https://example.test/fix/one.diff", "https://example.test/fix/two.diff",
		hashBytes(recordA), hashBytes(recordB), "operator-freeze",
	} {
		if !strings.Contains(dataMsg, want) {
			t.Fatalf("agent data message does not carry %q\n%s", want, dataMsg)
		}
	}
	if !strings.Contains(client.system, "read_material") {
		t.Fatal("advertised tool surface does not include read_material")
	}
	payloads := ""
	for _, o := range run.Observations {
		var payload map[string]any
		if json.Unmarshal(o.Payload, &payload) == nil {
			if content, ok := payload["content"].(string); ok {
				payloads += content
			}
		}
	}
	for _, want := range []string{string(recordB), string(fixA)} {
		if !strings.Contains(payloads, want) {
			t.Fatalf("tool observations do not carry the exact captured bytes %q\n%s", want, payloads)
		}
	}
}

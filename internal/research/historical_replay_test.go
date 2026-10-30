package research

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/flow"
	"github.com/fedorovmv/izyan/internal/evidencetools"
)

func historicalFixture(t *testing.T, schema string) string {
	t.Helper()
	r := validReport(t)
	r.Schema = schema
	if schema == ReportSchemaV1 { r.Decision = nil }
	if schema == ReportSchemaV3 || schema == ReportSchemaV4 { r.DecisionArtifact = validArtifact(t) }
	if schema == ReportSchemaV4 { r.RequestComposition = validRequestComposition(t) }
	dir := t.TempDir()
	writeLaneArtifacts(t, r, dir)
	// Fake-lane byte sizes are not real saved artifact sizes.
	for i := range r.VerifiedFacts { r.VerifiedFacts[i].Artifact.SizeBytes = 0 }
	if r.DecisionArtifact != nil { b, _ := json.Marshal(r.DecisionArtifact); writeFile(t, dir, "decision-artifact.json", b) }
	b, err := json.Marshal(r)
	if err != nil { t.Fatal(err) }
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil { t.Fatal(err) }
	var repairFixturePins func(any)
	repairFixturePins = func(value any) {
		switch v := value.(type) {
		case []any: for _, child := range v { repairFixturePins(child) }
		case map[string]any:
			if path, ok := v["path"].(string); ok && (path == "artifacts/obs-0001.json" || path == "artifacts/obs-0002.json") {
				raw, err := os.ReadFile(filepath.Join(dir, path)); if err != nil { t.Fatal(err) }
				v["sha256"] = shaOfBytes(raw)
				if _, ok := v["size_bytes"]; ok { v["size_bytes"] = len(raw) }
			}
			for _, child := range v { repairFixturePins(child) }
		}
	}
	repairFixturePins(doc)
	b, err = json.Marshal(doc)
	if err != nil { t.Fatal(err) }
	writeFile(t, dir, "report.json", b)
	return dir
}

func assertHistoricalPlayback(t *testing.T, dir string) {
	t.Helper()
	before, err := os.ReadFile(filepath.Join(dir, "report.json")); if err != nil { t.Fatal(err) }
	h, err := PrepareHistoricalReplay(t.Context(), dir)
	if err != nil { t.Fatal(err) }
	if !h.HistoricalOnly || h.CurrentAdmission || h.Schema != HistoricalReplaySchema { t.Fatalf("authority-bearing wrapper: %+v", h) }
	out := filepath.Join(t.TempDir(), "history")
	if err := h.Write(out); err != nil { t.Fatal(err) }
	after, err := os.ReadFile(filepath.Join(out, "original", "report.json")); if err != nil { t.Fatal(err) }
	if !bytes.Equal(before, after) { t.Fatal("historical report bytes changed") }
	for _, artifact := range h.Artifacts {
		info, err := os.Stat(filepath.Join(out, "original", filepath.FromSlash(artifact.Path))); if err != nil { t.Fatal(err) }
		if !info.ModTime().Equal(artifact.ModifiedAt) { t.Fatalf("timestamp changed for %s", artifact.Path) }
	}
	if _, err := os.Stat(filepath.Join(out, "report.json")); !os.IsNotExist(err) { t.Fatal("history published as current report") }
}

func TestHistoricalDecisionArtifactPlayback(t *testing.T) { assertHistoricalPlayback(t, historicalFixture(t, ReportSchemaV3)) }
func TestHistoricalRequestCompositionPlayback(t *testing.T) { assertHistoricalPlayback(t, historicalFixture(t, ReportSchemaV4)) }
func TestHistoricalSlice2Playback(t *testing.T) {
	for _, marker := range []string{Slice2ExtensionV1, Slice2Extension, Slice2ExtensionV3} {
		t.Run(marker, func(t *testing.T) {
			dir := historicalFixture(t, ReportSchemaV2)
			rewriteReport(t, dir, func(r *Report) { r.ContractExtensions = []string{marker}; if marker != Slice2ExtensionV3 { r.EvidenceLevel = nil } })
			assertHistoricalPlayback(t, dir)
		})
	}
}

func TestHistoricalReplayRejectsTamperedPins(t *testing.T) {
	dir := historicalFixture(t, ReportSchemaV2)
	raw, _ := os.ReadFile(filepath.Join(dir, "report.json")); r, _ := ParseReport(raw)
	writeFile(t, dir, r.VerifiedFacts[0].Artifact.Path, []byte("tampered"))
	if _, err := PrepareHistoricalReplay(t.Context(), dir); err == nil { t.Fatal("tampered pin accepted") }
}

func TestHistoricalReplayCannotPublishCurrentAuthority(t *testing.T) {
	dir := historicalFixture(t, ReportSchemaV4)
	h, err := PrepareHistoricalReplay(t.Context(), dir); if err != nil { t.Fatal(err) }
	raw, _ := json.Marshal(h)
	if _, err := ParseReport(raw); !errors.Is(err, ErrHistoricalAuthority) { t.Fatalf("wrong current admission refusal: %v", err) }
	out := filepath.Join(t.TempDir(), "history")
	if err := h.Write(out); err != nil { t.Fatal(err) }
	if _, err := LoadPersistedAgentTurn(out); !errors.Is(err, ErrHistoricalAuthority) { t.Fatalf("history reused as current turn: %v", err) }
	h.CurrentAdmission = true
	if err := h.Write(filepath.Join(t.TempDir(), "forged")); !errors.Is(err, ErrHistoricalAuthority) { t.Fatalf("authority override accepted: %v", err) }
}

func TestHistoricalReplayRejectsUnsafeWrites(t *testing.T) {
	dir := historicalFixture(t, ReportSchemaV2)
	h, err := PrepareHistoricalReplay(t.Context(), dir); if err != nil { t.Fatal(err) }
	for _, out := range []string{dir, filepath.Join(dir, "child"), t.TempDir()} { if err := h.Write(out); err == nil { t.Fatalf("unsafe output %s accepted", out) } }
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil { t.Fatal(err) }
	if err := os.Symlink(t.TempDir(), filepath.Join(link, "out")); err != nil { t.Fatal(err) }
	if err := h.Write(filepath.Join(link, "out")); err == nil { t.Fatal("symlink output accepted") }
	if err := os.Symlink(filepath.Join(dir, "report.json"), filepath.Join(dir, "alias.json")); err != nil { t.Fatal(err) }
	if _, err := PrepareHistoricalReplay(t.Context(), dir); err == nil { t.Fatal("symlink input accepted") }
}

func TestHistoricalFlowRequiresRecordedConfiguration(t *testing.T) {
	dir := historicalFixture(t, ReportSchemaV3)
	result := flow.Result{Events: []flow.Event{{Kind: flow.EventRunStart}}}
	raw, _ := json.Marshal(result); writeFile(t, dir, flowResultFile, raw)
	if _, err := PrepareHistoricalReplay(t.Context(), dir); err == nil { t.Fatal("missing configuration silently reconstructed") }
}

func TestHistoricalFlowRecordedPlayback(t *testing.T) {
	dir := historicalFixture(t, ReportSchemaV3)
	budget := flow.Budget{MaxSteps: 2, MaxActions: 2, StepsLeft: 2, ActionsLeft: 2}
	policy := flow.Policy{RequiredRules: []string{"historical-recorded-rule"}}
	result := flow.Result{RunID: "recorded", Termination: flow.TermNotDecisionReady, Policy: policy, Budget: budget,
		Events: []flow.Event{{Seq: 1, Kind: flow.EventRunStart, Policy: &policy, Budget: &budget}, {Seq: 2, Kind: flow.EventTerminated, Termination: flow.TermNotDecisionReady}}}
	raw, _ := json.Marshal(result); writeFile(t, dir, flowResultFile, raw)
	var events []byte
	for _, event := range result.Events { row, _ := json.Marshal(event); events = append(events, append(row, '\n')...) }
	writeFile(t, dir, flowEventsFile, events)
	writeFile(t, dir, flowObservationLedger, nil)
	assertHistoricalPlayback(t, dir)
	writeFile(t, dir, flowEventsFile, []byte("{}\n"))
	if _, err := PrepareHistoricalReplay(t.Context(), dir); err == nil { t.Fatal("conflicting recorded event sidecar accepted") }
}

func TestHistoricalReplayRejectsUnsafePins(t *testing.T) {
	for _, path := range []string{"../outside.json", "/absolute.json", "artifacts/../report.json", "artifacts\\outside.json"} {
		t.Run(path, func(t *testing.T) {
			dir := historicalFixture(t, ReportSchemaV2)
			rewriteReport(t, dir, func(r *Report) { r.VerifiedFacts[0].Artifact.Path = path })
			if _, err := PrepareHistoricalReplay(t.Context(), dir); err == nil { t.Fatal("unsafe artifact path accepted") }
		})
	}
}

func TestHistoricalReplayPreservesInvalidRawArtifacts(t *testing.T) {
	dir := historicalFixture(t, ReportSchemaV1)
	writeFile(t, dir, "agent/failed/result.json", []byte("not valid JSON: saved failed harness output"))
	assertHistoricalPlayback(t, dir)
}

func TestHistoricalNamedManifestPins(t *testing.T) {
	for _, pair := range [][2]string{{"prompt_path", "prompt_sha256"}, {"rendered_prompt_path", "rendered_prompt_sha256"}, {"e6_preflight_report", "e6_preflight_sha256"}, {"report_path", "report_sha256"}} {
		for _, location := range []string{"agent_manifest", "agent", "decision_ready", "turn-prompt"} {
			t.Run(location+"/"+pair[0], func(t *testing.T) {
				for _, mutation := range []string{"valid", "tamper", "missing", "missing-digest", "missing-path", "escape", "absolute-outside", "absolute-retained"} {
					t.Run(mutation, func(t *testing.T) {
						dir := historicalFixture(t, ReportSchemaV3)
						path := "agent/retained.txt"
						data := []byte("original recorded artifact")
						writeFile(t, dir, path, data)
						if mutation == "escape" { path = "../retained.txt" }
						if mutation == "absolute-outside" { path = filepath.Join(t.TempDir(), "retained.txt"); if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) } }
						if mutation == "absolute-retained" { path = filepath.Join(dir, path) }
						pin := map[string]any{pair[0]: path, pair[1]: shaOfBytes(data)}
						if mutation == "missing-digest" { delete(pin, pair[1]) }
						if mutation == "missing-path" { delete(pin, pair[0]) }
						var manifest any = pin
						if pair[0] == "report_path" { manifest = map[string]any{"preflight_attempts": []any{pin}} }
						doc := map[string]any{"schema": "research-run-manifest/1"}
						switch location {
						case "agent": doc[location] = map[string]any{"manifest": manifest}
						case "decision_ready": doc[location] = map[string]any{"turns": []any{map[string]any{"role": "plan", "manifest": manifest}}}
						case "turn-prompt": doc["decision_ready"] = map[string]any{"turns": []any{manifest}}
						default: doc[location] = manifest
						}
						raw, err := json.Marshal(doc); if err != nil { t.Fatal(err) }; writeFile(t, dir, "run-manifest.json", raw)
						if mutation == "tamper" { writeFile(t, dir, "agent/retained.txt", []byte("altered")) }
						if mutation == "missing" { if err := os.Remove(filepath.Join(dir, "agent/retained.txt")); err != nil { t.Fatal(err) } }
						if mutation == "valid" || mutation == "absolute-retained" { assertHistoricalPlayback(t, dir) } else if _, err := PrepareHistoricalReplay(t.Context(), dir); err == nil { t.Fatal("invalid named artifact pin accepted") }
					})
				}
			})
		}
	}
}

func writeHistoricalFlow(t *testing.T, dir string, result flow.Result, audit []evidencetools.AuditRecord) {
	t.Helper()
	raw, err := json.Marshal(result); if err != nil { t.Fatal(err) }; writeFile(t, dir, flowResultFile, raw)
	var events, ledger []byte
	for _, event := range result.Events { row, err := json.Marshal(event); if err != nil { t.Fatal(err) }; events = append(events, append(row, '\n')...) }
	for _, record := range audit { row, err := json.Marshal(record); if err != nil { t.Fatal(err) }; ledger = append(ledger, append(row, '\n')...) }
	writeFile(t, dir, flowEventsFile, events)
	writeFile(t, dir, flowObservationLedger, ledger)
}

func TestHistoricalFlowAuditContentBinding(t *testing.T) {
	for _, mutation := range []string{"valid", "digest", "status", "completeness", "scope", "evidence", "limitations", "arguments", "tool", "observation-tool", "action-id", "missing-row", "duplicate-row", "audit-payload"} {
		t.Run(mutation, func(t *testing.T) {
			dir := historicalFixture(t, ReportSchemaV3)
			action := flow.PlanAction{ID: "recorded-action", AdapterID: "historical-tool", Arguments: json.RawMessage(`{"symbol":"original"}`)}
			o := &evidencetools.Observation{ID: "OBS-1000", Tool: "historical_tool", ToolStatus: evidencetools.StatusOK, Completeness: evidencetools.CompletenessComplete, Scope: "recorded scope", Data: map[string]any{"answer": "recorded"}}
			digest, err := canonicalObservationDigest(o); if err != nil { t.Fatal(err) }
			observation := flow.Observation{ID: o.ID, ActionID: action.ID, Status: string(o.ToolStatus), Completeness: string(o.Completeness), Scope: o.Scope, DataDigest: digest, AuditBound: true}
			audit := []evidencetools.AuditRecord{{Tool: o.Tool, Args: append(json.RawMessage(nil), action.Arguments...), Observation: o}}
			switch mutation {
			case "digest": observation.DataDigest = testDigest
			case "status": observation.Status = flow.ObsStatusError
			case "completeness": observation.Completeness = flow.ObsUnknown
			case "scope": observation.Scope = "forged scope"
			case "evidence": observation.EvidenceRefs = []string{"forged"}
			case "limitations": observation.Limitations = []string{"forged"}
			case "arguments": action.Arguments = json.RawMessage(`{"symbol":"forged"}`)
			case "tool": action.AdapterID = "another-tool"
			case "observation-tool": o.Tool = "another_tool"; observation.DataDigest, err = canonicalObservationDigest(o); if err != nil { t.Fatal(err) }
			case "action-id": observation.ActionID = "not-executed"
			case "missing-row": audit = nil
			case "duplicate-row": audit = append(audit, audit[0])
			case "audit-payload": o.Data = map[string]any{"answer": "altered"}
			}
			budget := flow.Budget{MaxSteps: 2, MaxActions: 2}
			policy := flow.Policy{RequiredRules: []string{"retired-rule"}}
			result := flow.Result{RunID: "recorded", Policy: policy, Budget: budget, Termination: flow.TermNotDecisionReady, Actions: []flow.PlanAction{action}, Observations: []flow.Observation{observation}, Events: []flow.Event{
				{Seq: 1, Kind: flow.EventRunStart, Policy: &policy, Budget: &budget},
				{Seq: 2, Kind: flow.EventAction, Action: &action},
				{Seq: 3, Kind: flow.EventObservation, Observation: &observation},
				{Seq: 4, Kind: flow.EventTerminated, Termination: flow.TermNotDecisionReady},
			}}
			writeHistoricalFlow(t, dir, result, audit)
			if mutation == "valid" { assertHistoricalPlayback(t, dir) } else if _, err := PrepareHistoricalReplay(t.Context(), dir); err == nil { t.Fatal("forged flow copies accepted despite contradictory audit") }
		})
	}
}

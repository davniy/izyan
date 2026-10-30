package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/research"
)

// TestResearchDecisionCLIReplayPlan: a replayed turn whose retained answer
// carries a valid verification plan drives the bounded phase over the same
// confined session — new sibling artifacts appear, the decision cites
// persisted verification observations, and the whole report validates.
func TestResearchDecisionCLIReplayPlan(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	plan := `,"verification_plan":{"falsifier":{
	  "kind":"package-absent","condition_id":"cond-1",
	  "module":"example.com/usagedep","package":"example.com/usagedep/testonly",
	  "statement":"the vulnerable package is absent from the product build closure",
	  "scope":"paired product/test build closures"},
	  "checks":[{"id":"v1","tool":"usage-scope",
	    "arguments":{"module":"example.com/usagedep","package":"example.com/usagedep/testonly"},
	    "purpose":"classify the declared package in both build closures","condition_id":"cond-1"}]}`

	replayDir := writeDecisionReplayRun(t, plan)
	out := filepath.Join(t.TempDir(), "out")
	if err := runResearch(researchArgs(root, adv, out, replayDir)); err != nil {
		t.Fatalf("runResearch: %v", err)
	}

	// Current publication must validate with the real replayed decision and
	// canonical requested-case binding, independently of the default wire version.
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Disposition struct {
			Class     string `json:"class"`
			AutoClose bool   `json:"auto_close"`
		} `json:"disposition"`
		Decision *struct {
			Verdict      string   `json:"verdict"`
			EvidenceRefs []string `json:"evidence_refs"`
			Checks       []struct {
				ID, Tool, Status, Completeness string
			} `json:"checks"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatalf("report.json decode: %v", err)
	}
	report, err := research.ParseReport(rb)
	if err != nil {
		t.Fatalf("parse current report: %v", err)
	}
	if err := research.Validate(report, out); err != nil {
		t.Fatalf("validate current replay publication: %v", err)
	}
	if doc.Decision == nil {
		t.Fatal("no decision in report")
	}
	t.Logf("decision verdict=%s refs=%v", doc.Decision.Verdict, doc.Decision.EvidenceRefs)
	if doc.Disposition.Class != "REVIEW_REQUIRED" || doc.Disposition.AutoClose {
		t.Fatalf("disposition=%+v", doc.Disposition)
	}
	// Verification ran: one executed check row bound to a persisted
	// verification observation.
	if len(doc.Decision.Checks) != 1 || doc.Decision.Checks[0].Tool != "usage-scope" {
		t.Fatalf("checks=%+v", doc.Decision.Checks)
	}
	for _, ref := range doc.Decision.EvidenceRefs {
		if !strings.HasPrefix(ref, "obs:") {
			t.Fatalf("decision ref %q does not name a persisted observation", ref)
		}
	}

	// Sibling artifacts exist; originals are untouched by the phase.
	for _, name := range []string{"verification-observations.jsonl", "verification-facts.json", "report.md", "run-manifest.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	// verification-observations.jsonl holds session audit records whose
	// observation ids continue the lane's numbering — no collision with
	// observations.jsonl.
	laneIDs := observationIDs(t, filepath.Join(out, "observations.jsonl"))
	verIDs := observationIDs(t, filepath.Join(out, "verification-observations.jsonl"))
	if len(verIDs) == 0 {
		t.Fatal("verification-observations.jsonl is empty")
	}
	for id := range verIDs {
		if laneIDs[id] {
			t.Fatalf("verification observation id %s collides with the deterministic lane", id)
		}
	}
	// verification-facts.json records the executed plan and the pins
	// that grounded the decision.
	var vf struct {
		Executed bool `json:"executed"`
		Checks   []struct {
			ObservationID string   `json:"observation_id"`
			Pins          []string `json:"pins"`
		} `json:"checks"`
	}
	vb, err := os.ReadFile(filepath.Join(out, "verification-facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(vb, &vf); err != nil {
		t.Fatalf("verification-facts decode: %v", err)
	}
	if !vf.Executed || len(vf.Checks) != 1 || vf.Checks[0].ObservationID == "" || len(vf.Checks[0].Pins) == 0 {
		t.Fatalf("verification-facts=%+v", vf)
	}
	// The manifest records the verification phase.
	mb, err := os.ReadFile(filepath.Join(out, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mb), `"plan_status": "executed"`) {
		t.Fatal("run-manifest.json lacks the verification record")
	}
}

// TestResearchDecisionCLINoPlan: a replayed turn with no plan lets the
// deterministic applicability chain decide on its own — this fixture's
// declared package is proven absent from the product import closure, so
// the decision is NOT_AFFECTED citing the carrier observation — and the
// verification phase is still recorded as not executed with no
// verification observations file emitted.
func TestResearchDecisionCLINoPlan(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	replayDir := writeDecisionReplayRun(t, "")
	out := filepath.Join(t.TempDir(), "out")
	if err := runResearch(researchArgs(root, adv, out, replayDir)); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Decision *struct {
			Verdict string `json:"verdict"`
			Reason  string `json:"reason"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Decision == nil || doc.Decision.Verdict != "NOT_AFFECTED" {
		t.Fatalf("decision=%+v", doc.Decision)
	}
	if !strings.Contains(doc.Decision.Reason, "not linked into any product binary") {
		t.Fatalf("no-plan decision must carry the applicability chain reason: %q", doc.Decision.Reason)
	}
	if _, err := os.Stat(filepath.Join(out, "verification-observations.jsonl")); !os.IsNotExist(err) {
		t.Fatal("verification-observations.jsonl written without an executed plan")
	}
	vb, err := os.ReadFile(filepath.Join(out, "verification-facts.json"))
	if err != nil {
		t.Fatal("verification-facts.json must record the skipped phase")
	}
	var vf struct {
		Executed   bool   `json:"executed"`
		PlanStatus string `json:"plan_status"`
	}
	if err := json.Unmarshal(vb, &vf); err != nil {
		t.Fatal(err)
	}
	if vf.Executed || !strings.Contains(vf.PlanStatus, "no verification plan") {
		t.Fatalf("verification-facts=%+v", vf)
	}
}

// TestResearchDecisionCLIDeterministicOnly: ordinary offline research emits a
// decision without an agent turn. The deterministic applicability chain proves
// this fixture's package absent, so the decision is NOT_AFFECTED.
func TestResearchDecisionCLIDeterministicOnly(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	out := filepath.Join(t.TempDir(), "out")
	args := researchArgs(root, adv, out, "")
	if err := runResearch(args); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		AgentOutput struct {
			Status string `json:"status"`
		} `json:"agent_output"`
		Decision *struct {
			Verdict string `json:"verdict"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(rb, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.AgentOutput.Status != "NOT_REQUESTED" {
		t.Fatalf("agent_output.status=%q", doc.AgentOutput.Status)
	}
	if doc.Decision == nil || doc.Decision.Verdict != "NOT_AFFECTED" {
		t.Fatalf("decision=%+v", doc.Decision)
	}
}

// observationIDs decodes an audit ledger file into its observation ids.
func observationIDs(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var row struct {
			Observation *struct {
				ID string `json:"id"`
			} `json:"observation"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if row.Observation != nil {
			ids[row.Observation.ID] = true
		}
	}
	return ids
}

// TestNoAnalyzeIntegration: the research lane never constructs the old
// analyze workflow — neither the CLI wiring nor internal/research may
// import the old states/report/risk/llm analysis packages.
func TestNoAnalyzeIntegration(t *testing.T) {
	forbidden := []string{
		`"github.com/fedorovmv/izyan/internal/states"`,
		`"github.com/fedorovmv/izyan/internal/report"`,
		`"github.com/fedorovmv/izyan/internal/risk"`,
		`"github.com/fedorovmv/izyan/internal/llm"`,
	}
	var sources []string
	for _, pat := range []string{"research.go", "../../internal/research/*.go"} {
		matches, err := filepath.Glob(pat)
		if err != nil || len(matches) == 0 {
			t.Fatalf("glob %s: %v", pat, err)
		}
		sources = append(sources, matches...)
	}
	for _, src := range sources {
		if strings.HasSuffix(src, "_test.go") {
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if strings.Contains(string(b), bad) {
				t.Fatalf("%s imports forbidden old-workflow package %s", src, bad)
			}
		}
	}
}

// TestVerificationArtifacts exercises the persistence helpers directly:
// index pins come only from session audit records — never from the trace
// observation's own copy — renumbering moves session-minted ids past the
// lane's sequence, and unmatched audit records contribute nothing.
func TestVerificationArtifacts(t *testing.T) {
	lane := &research.LaneResult{
		Observations: []*evidencetools.Observation{
			{ID: "OBS-0001", Tool: "a"}, {ID: "OBS-0003", Tool: "b"},
		},
	}
	trace := &research.VerificationTrace{
		Requests: []research.VerificationRequest{
			{ID: "v1", Tool: "usage-scope"}, {ID: "v2", Tool: "read_source"},
		},
		Observations: []*evidencetools.Observation{
			// session-minted ids deliberately collide with the lane's.
			{ID: "OBS-0001", Tool: "usage-scope", EvidenceRefs: []string{"sha256:" + strings.Repeat("aa", 32)}},
			{ID: "OBS-0002", Tool: "read_source", EvidenceRefs: []string{"src:main.go#L1"}},
		},
	}
	audit := []evidencetools.AuditRecord{
		{Tool: "usage-scope", Observation: &evidencetools.Observation{
			ID: "OBS-0001", Data: map[string]any{"usage_scope": "test-only"},
			EvidenceRefs: []string{"sha256:" + strings.Repeat("aa", 32)}}},
		{Tool: "unrelated", Observation: &evidencetools.Observation{ID: "OBS-9999"}},
	}
	renumberVerification(trace, audit, lane)
	if trace.Observations[0].ID != "OBS-0004" || trace.Observations[1].ID != "OBS-0005" {
		t.Fatalf("renumbered ids: %s %s", trace.Observations[0].ID, trace.Observations[1].ID)
	}
	if audit[0].Observation.ID != "OBS-0004" {
		t.Fatalf("audit record id not renumbered: %s", audit[0].Observation.ID)
	}
	if audit[1].Observation.ID != "OBS-9999" {
		t.Fatalf("unmatched audit record rewritten: %s", audit[1].Observation.ID)
	}
	idx := research.VerificationObservationIndex(trace, audit)
	data, _ := json.Marshal(map[string]any{"usage_scope": "test-only"})
	sum := sha256.Sum256(data)
	want := "sha256:" + hex.EncodeToString(sum[:])
	pins := idx["OBS-0004"]
	if len(pins) != 2 || pins[0] != want || pins[1] != "sha256:"+strings.Repeat("aa", 32) {
		t.Fatalf("pins=%v want data digest %s + session refs", pins, want)
	}
	if _, ok := idx["OBS-9999"]; ok {
		t.Fatal("unmatched audit record entered the index")
	}
	if _, ok := idx["OBS-0005"]; ok {
		t.Fatal("observation without an audit record gained pins")
	}

	out := t.TempDir()
	arts, err := writeVerificationArtifacts(out, trace, audit)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 2 {
		t.Fatalf("artifacts=%v", arts)
	}
	b, err := os.ReadFile(filepath.Join(out, "verification-observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"OBS-0004"`) {
		t.Fatal("ledger missing renumbered observation")
	}
	// verificationManifest marks a skipped phase honestly.
	m := verificationManifest(nil, "no verification plan in the retained answer", nil)
	if m["executed"] != false || m["decision_verdict"] != nil {
		t.Fatalf("manifest=%+v", m)
	}
}

// TestReplayKeepsRecordedPrompt: a run persisted against the frozen v1
// prompt replays with its own recorded prompt pin — the new run's manifest
// carries the original prompt_path/prompt_sha256 verbatim, never the
// current default.
func TestReplayKeepsRecordedPrompt(t *testing.T) {
	root, adv := decisionFixtureRoot(t), writeDecisionAdvisory(t)
	replayDir := writeDecisionReplayRun(t, "")
	out := filepath.Join(t.TempDir(), "out")
	if err := runResearch(researchArgs(root, adv, out, replayDir)); err != nil {
		t.Fatalf("runResearch: %v", err)
	}
	mb, err := os.ReadFile(filepath.Join(out, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Agent struct {
			Manifest struct {
				PromptPath   string `json:"prompt_path"`
				PromptSHA256 string `json:"prompt_sha256"`
			} `json:"manifest"`
			ReplayedFrom string `json:"replayed_from"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	if m.Agent.Manifest.PromptPath != "eval/agent7/prompts/r0-v1.txt" ||
		m.Agent.Manifest.PromptSHA256 != "55b01e9a505bd058cb7be568f08c0e58364b8048e5acea030a14534f7031a0ae" {
		t.Fatalf("replayed run carried prompt pin path=%q sha=%q — expected the recorded r0-v1 pin",
			m.Agent.Manifest.PromptPath, m.Agent.Manifest.PromptSHA256)
	}
	if m.Agent.ReplayedFrom != replayDir {
		t.Fatalf("replayed_from=%q want %q", m.Agent.ReplayedFrom, replayDir)
	}
}

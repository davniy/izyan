package main

// Target/build identity tests for the triage CLI. The product build is what
// the captured inputs identify; the analyzer host is only the platform the
// toolchain happens to run on. These tests pin that distinction end to end:
// the evidence session, the agent-visible data message, the per-attempt audit
// record and every stability retry describe the resolved selection or state
// that no product build target was identified.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	triage "github.com/davniy/izyan/internal/productb/triage"
)

// operatorBuild is the build-selection object an operator supplies either in
// finding.target.build or in the investigation-inputs.v1 `build` member.
func operatorBuild(goos, goarch string, tags []string, cgo bool) map[string]any {
	return map[string]any{
		"goos": goos, "goarch": goarch, "build_tags": tags,
		"cgo_enabled": cgo, "source": "operator-declared", "scope": "operator",
	}
}

// findingWithBuild attaches a declared product build to a finding fixture.
func findingWithBuild(id, repo string, build map[string]any) map[string]any {
	f := triageFinding(id, repo)
	target := f["target"].(map[string]any)
	target["build"] = build
	return f
}

// writeBuildManifest writes an investigation-inputs.v1 manifest carrying
// only the optional build input; no captured advisory/fix records are needed
// to exercise target resolution.
func writeBuildManifest(t *testing.T, build map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	manifest, err := json.Marshal(map[string]any{
		"schema_version": "investigation-inputs.v1",
		"build":          build,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "investigation-inputs.json")
	if err := os.WriteFile(path, manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// recordedMessage is the part of a raw-agent transcript the target tests
// inspect: role plus the exact content the model saw or the tool returned.
type recordedMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// recordedTranscript covers the primary run and its stability retries.
type recordedTranscript struct {
	Messages      []recordedMessage `json:"messages"`
	StabilityRuns []struct {
		Messages []recordedMessage `json:"messages"`
	} `json:"stability_runs"`
}

// readTranscript loads raw-agent.json as the recorded messages.
func readTranscript(t *testing.T, dir string) recordedTranscript {
	t.Helper()
	var doc recordedTranscript
	if err := json.Unmarshal(assertFile(t, filepath.Join(dir, "raw-agent.json")), &doc); err != nil {
		t.Fatalf("raw-agent.json: %v", err)
	}
	return doc
}

// recordedSnapshot extracts the get_product_snapshot observation data the
// agent actually received from the evidence session.
func recordedSnapshot(t *testing.T, dir string) domain.ProductSnapshot {
	t.Helper()
	for _, msg := range readTranscript(t, dir).Messages {
		if msg.Role != "tool" {
			continue
		}
		var obs triage.ToolObservation
		if err := json.Unmarshal([]byte(msg.Content), &obs); err != nil {
			continue
		}
		if obs.Tool != "get_product_snapshot" || len(obs.Data) == 0 {
			continue
		}
		// ToolObservation.Data is the serialized evidence Observation;
		// its own `data` member carries the product snapshot.
		var evidence struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(obs.Data, &evidence); err != nil || len(evidence.Data) == 0 {
			t.Fatalf("get_product_snapshot observation payload: %v", err)
		}
		var snap domain.ProductSnapshot
		if err := json.Unmarshal(evidence.Data, &snap); err != nil {
			t.Fatalf("get_product_snapshot data: %v", err)
		}
		return snap
	}
	t.Fatal("recorded run has no get_product_snapshot observation")
	return domain.ProductSnapshot{}
}

// detToolEvents returns the per-attempt det_tools audit events.
func detToolEvents(t *testing.T, dir string) []triage.AuditEvent {
	t.Helper()
	var out []triage.AuditEvent
	for _, line := range strings.Split(string(assertFile(t, filepath.Join(dir, "audit", "events.jsonl"))), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev triage.AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit event: %v", err)
		}
		if ev.Type == triage.AuditEventDetTools {
			out = append(out, ev)
		}
	}
	return out
}

// buildAuditLines returns the target/analysis-platform lines of every
// det_tools event, one slice per attempt.
func buildAuditLines(events []triage.AuditEvent) [][]string {
	var out [][]string
	for _, ev := range events {
		if ev.DetTools == nil {
			continue
		}
		var lines []string
		for _, lim := range ev.DetTools.Limitations {
			if strings.Contains(lim, "product build target") {
				lines = append(lines, lim)
			}
		}
		out = append(out, lines)
	}
	return out
}

// promptDataMessage returns the initial untrusted data message the run
// persisted in prompt-input.v1.
func promptDataMessage(t *testing.T, dir string) string {
	t.Helper()
	var pi triage.PromptInput
	if err := json.Unmarshal(assertFile(t, filepath.Join(dir, "prompt-input.json")), &pi); err != nil {
		t.Fatalf("prompt-input.json: %v", err)
	}
	if len(pi.Messages) == 0 {
		t.Fatal("prompt-input.json carries no initial messages")
	}
	return pi.Messages[0].Content
}

func wantProductTarget(t *testing.T, got *domain.ProductTarget, goos, goarch string, tags []string, cgo bool) {
	t.Helper()
	if got == nil {
		t.Fatal("no resolved product target")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("resolved target is invalid: %v", err)
	}
	if got.GOOS != goos || got.GOARCH != goarch {
		t.Fatalf("target platform = %s/%s, want %s/%s", got.GOOS, got.GOARCH, goos, goarch)
	}
	if strings.Join(got.BuildTags, ",") != strings.Join(tags, ",") {
		t.Fatalf("target build tags = %v, want %v", got.BuildTags, tags)
	}
	if got.CGOEnabled != cgo {
		t.Fatalf("target cgo = %v, want %v (target=%+v)", got.CGOEnabled, cgo, *got)
	}
	if got.Source != domain.ProductTargetSourceOperatorDeclared || got.Scope != domain.ProductTargetScopeOperator {
		t.Fatalf("target provenance = %s/%s, want operator-declared/operator", got.Source, got.Scope)
	}
}

// TestTriageTargetOverridesHost proves the identified Linux/amd64 build wins
// over the analyzer host for both declaration channels: finding.target.build
// and the investigation-inputs.v1 build member. Tags and explicit CGO travel
// with the selection into the session, the agent data message and the audit.
func TestTriageTargetOverridesHost(t *testing.T) {
	cases := []struct {
		name  string
		input func(t *testing.T, id, repo string) string
	}{
		{
			name: "finding declaration",
			input: func(t *testing.T, id, repo string) string {
				return writeFindings(t, findingWithBuild(id, repo, operatorBuild("linux", "amd64", []string{"netgo"}, true)))
			},
		},
		{
			name: "bundle declaration",
			input: func(t *testing.T, id, repo string) string {
				return writeFindings(t, triageFinding(id, repo))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
			triageEnv(t, srv.URL)
			repo := cliFixtureRepo(t)
			input := tc.input(t, "target-host-1", repo)
			out := filepath.Join(t.TempDir(), "out")
			args := []string{"--input", input, "--out", out}
			if tc.name == "bundle declaration" {
				args = append(args, "--investigation-inputs", writeBuildManifest(t, operatorBuild("linux", "amd64", []string{"netgo"}, true)))
			}
			if err := runTriage(args); err != nil {
				t.Fatalf("triage with declared target: %v", err)
			}
			dir := runDir(t, out, "target-host-1")

			snap := recordedSnapshot(t, dir)
			// The evidence probe may report its own effective analysis
			// platform (host context). It must never present a *different*
			// scoped product build than the resolved one.
			if snap.Target != nil && snap.Target.Scoped() {
				wantProductTarget(t, snap.Target, "linux", "amd64", []string{"netgo"}, true)
			}
			projection := assertFile(t, filepath.Join(dir, "investigation-inputs.json"))
			if !strings.Contains(string(projection), `"build_target"`) || !strings.Contains(string(projection), `"cgo_enabled": true`) {
				t.Fatalf("material projection does not carry the resolved build: %s", projection)
			}

			msg := promptDataMessage(t, dir)
			for _, want := range []string{
				`"product_target":{"goos":"linux","goarch":"amd64"`,
				`"analysis_platform":"linux/amd64"`,
				"build_tags",
			} {
				if !strings.Contains(msg, want) {
					t.Fatalf("agent data message lacks %q: %s", want, msg)
				}
			}
			if strings.Contains(msg, `"analysis_context_only":true`) {
				t.Fatalf("agent data message marks an identified target as analysis context only: %s", msg)
			}

			events := detToolEvents(t, dir)
			if len(events) == 0 {
				t.Fatal("run recorded no det_tools audit event")
			}
			lines := buildAuditLines(events)[0]
			if len(lines) != 1 || !strings.Contains(lines[0], "product build target: linux/amd64") ||
				!strings.Contains(lines[0], "tags=[netgo]") || !strings.Contains(lines[0], "cgo=true") {
				t.Fatalf("det_tools audit does not describe the declared build: %v", lines)
			}
		})
	}
}

// TestTriageMissingTargetRemainsAnalysisContext proves absent target
// information stays absent: the session records the host as its analysis
// platform, the agent message says no product target was identified, the
// audit keeps the distinction, and build-dependent negative admission still
// rejects the recorded snapshot.
func TestTriageMissingTargetRemainsAnalysisContext(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	triageEnv(t, srv.URL)
	repo := cliFixtureRepo(t)
	finding := triageFinding("missing-target-1", repo)
	// A claimed release toolchain is not a product target either.
	finding["target"].(map[string]any)["toolchain"] = "go1.25.8"
	input := writeFindings(t, finding)
	out := filepath.Join(t.TempDir(), "out")
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("triage without a target: %v", err)
	}
	dir := runDir(t, out, "missing-target-1")

	snap := recordedSnapshot(t, dir)
	if snap.Target != nil && snap.Target.Scoped() {
		t.Fatalf("host platform was presented as a product target: %+v", snap.Target)
	}
	if snap.Target != nil {
		if err := snap.Target.Validate(); err != nil {
			t.Fatalf("recorded analysis target is invalid: %v", err)
		}
		if snap.Target.Source != domain.ProductTargetSourceHostDefault {
			t.Fatalf("analysis target source = %q, want host-default", snap.Target.Source)
		}
	}
	if snap.GOOS != runtime.GOOS || snap.GOARCH != runtime.GOARCH {
		t.Fatalf("analysis platform = %s/%s, want the host %s/%s", snap.GOOS, snap.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if err := domain.ValidateNegativeTarget(snap); err == nil {
		t.Fatal("build-dependent negative admission accepted a snapshot with no identified product target")
	}

	msg := promptDataMessage(t, dir)
	if !strings.Contains(msg, "No product build target was identified") {
		t.Fatalf("agent data message does not name the missing target: %s", msg)
	}
	if !strings.Contains(msg, `"analysis_context_only":true`) || strings.Contains(msg, `"product_target"`) {
		t.Fatalf("agent build context does not distinguish host analysis from a product target: %s", msg)
	}

	events := detToolEvents(t, dir)
	if len(events) == 0 {
		t.Fatal("run recorded no det_tools audit event")
	}
	lines := buildAuditLines(events)[0]
	if len(lines) != 1 || !strings.Contains(lines[0], "no product build target was identified") {
		t.Fatalf("det_tools audit does not record the absent product target: %v", lines)
	}

	// No target was invented from the finding's claimed toolchain or go.mod.
	projection := assertFile(t, filepath.Join(dir, "investigation-inputs.json"))
	if strings.Contains(string(projection), `"build_target"`) {
		t.Fatalf("run with no build input persisted a resolved target: %s", projection)
	}
}

// TestTriageTargetConflictRejected proves contradictory finding and bundle
// declarations fail before any session/model work instead of either one
// silently winning.
func TestTriageTargetConflictRejected(t *testing.T) {
	cases := []struct {
		name   string
		finder map[string]any
		bundle map[string]any
		want   string
	}{
		{
			name:   "platform",
			finder: operatorBuild("linux", "amd64", []string{"netgo"}, false),
			bundle: operatorBuild("linux", "arm64", []string{"netgo"}, false),
			want:   "goarch",
		},
		{
			name:   "tags and cgo",
			finder: operatorBuild("linux", "amd64", []string{"netgo"}, true),
			bundle: operatorBuild("linux", "amd64", []string{"osusergo"}, false),
			want:   "build_tags",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, models := fakeTriageLLM(t, staticReply(cliAssessmentDet))
			triageEnv(t, srv.URL)
			input := writeFindings(t, findingWithBuild("target-conflict-1", cliFixtureRepo(t), tc.finder))
			out := filepath.Join(t.TempDir(), "out")
			err := runTriage([]string{"--input", input, "--out", out, "--investigation-inputs", writeBuildManifest(t, tc.bundle)})
			wantExit(t, err, triage.ExitCodeError)
			matches, _ := filepath.Glob(filepath.Join(out, "*", "error.json"))
			if len(matches) != 1 {
				t.Fatalf("conflict produced %d error records, want 1 (%v)", len(matches), err)
			}
			var doc triage.ErrorDocument
			if uerr := json.Unmarshal(assertFile(t, matches[0]), &doc); uerr != nil {
				t.Fatalf("error.json: %v", uerr)
			}
			if !strings.Contains(doc.Error, "conflicting product build declarations") || !strings.Contains(doc.Error, tc.want) {
				t.Fatalf("conflict error = %q, want a conflicting-declaration error naming %s", doc.Error, tc.want)
			}
			if len(*models) != 0 {
				t.Fatalf("conflicting declarations reached the model (%d calls)", len(*models))
			}
			if decisions, _ := filepath.Glob(filepath.Join(out, "*", "decision.json")); len(decisions) != 0 {
				t.Fatalf("conflicting declarations produced a decision package: %v", decisions)
			}
		})
	}
}

// TestTriageRetriesKeepBuildIdentity proves one resolved build selection is
// shared by every stability attempt: each attempt's det_tools audit and its
// agent-visible data message carry the same target.
func TestTriageRetriesKeepBuildIdentity(t *testing.T) {
	srv, _ := fakeTriageLLM(t, func(call int) triageReply {
		if call%2 == 0 {
			return triageReply{toolCalls: []map[string]any{{
				"id": "call-1", "type": "function",
				"function": map[string]any{"name": "get_product_snapshot", "arguments": "{}"},
			}}}
		}
		return triageReply{content: cliAssessmentDet}
	})
	triageEnv(t, srv.URL)
	config := filepath.Join(t.TempDir(), "triage-site.json")
	if err := os.WriteFile(config, []byte(`{"schema_version":"triage-site.v1","policy":{"on_drift":"error","stability_retries":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	input := writeFindings(t, findingWithBuild("retry-target-1", cliFixtureRepo(t), operatorBuild("linux", "amd64", []string{"netgo"}, true)))
	out := filepath.Join(t.TempDir(), "out")
	if err := runTriage([]string{"--input", input, "--out", out, "--config", config}); err != nil {
		t.Fatalf("triage with a stability retry: %v", err)
	}
	dir := runDir(t, out, "retry-target-1")

	events := detToolEvents(t, dir)
	if len(events) != 2 {
		t.Fatalf("det_tools events = %d, want one per attempt (2)", len(events))
	}
	if events[0].Attempt != 0 || events[1].Attempt != 2 {
		t.Fatalf("det_tools attempts = %d,%d, want 0,2", events[0].Attempt, events[1].Attempt)
	}
	lines := buildAuditLines(events)
	if len(lines) != 2 || len(lines[0]) != 1 || len(lines[1]) != 1 {
		t.Fatalf("target audit lines = %v; events=%+v", lines, events)
	}
	if lines[0][0] != lines[1][0] {
		t.Fatalf("stability attempts describe different builds:\n  attempt 1: %s\n  retry:     %s", lines[0][0], lines[1][0])
	}
	if !strings.Contains(lines[0][0], "product build target: linux/amd64") {
		t.Fatalf("retry audit does not carry the resolved target: %s", lines[0][0])
	}

	tr := readTranscript(t, dir)
	if len(tr.StabilityRuns) != 1 || len(tr.StabilityRuns[0].Messages) == 0 {
		t.Fatalf("stability retry transcript missing: %+v", tr.StabilityRuns)
	}
	if !strings.Contains(tr.StabilityRuns[0].Messages[0].Content, `"product_target":{"goos":"linux","goarch":"amd64"`) {
		t.Fatalf("retry data message does not carry the resolved target: %s", tr.StabilityRuns[0].Messages[0].Content)
	}
}

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	triage "github.com/davniy/izyan/internal/productb/triage"
)

// tripwireTransport fails every request and counts it. Installing it as
// http.DefaultTransport proves that a captured research call issued no
// network request: the captured providers and the evidence session construct
// no transport of their own, so any fallback would surface here instead of
// silently reaching an upstream endpoint.
type tripwireTransport struct {
	hits atomic.Int64
}

func (t *tripwireTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.hits.Add(1)
	return nil, errors.New("network access attempted by a captured-only test: " + r.URL.String())
}

// triageEnv pins the LLM_* variables consumed by llm.ConfigFromEnv so the
// ambient developer/CI environment can never leak into triage tests.
// LLM_ENABLED is truthy and BaseURL points at the fake endpoint.
func triageEnv(t *testing.T, baseURL string) {
	t.Helper()
	for _, k := range []string{
		"LLM_ENABLED", "LLM_BASE_URL", "LLM_API_KEY",
		"LLM_ANALYZE_MODEL", "LLM_BUILD_MODEL",
		"LLM_TIMEOUT_SEC", "LLM_MAX_TOKENS", "LLM_INSECURE_TLS",
		"LLM_BUILD_MAX_RETRIES",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("LLM_ENABLED", "1")
	t.Setenv("LLM_BASE_URL", baseURL)
	t.Setenv("LLM_API_KEY", "test-key")
	t.Setenv("LLM_ANALYZE_MODEL", "triage-model")
}

// triageReply is one scripted assistant message for the fake endpoint.
type triageReply struct {
	content   string
	toolCalls []map[string]any
}

type triageReqMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// requestFindingID extracts the finding_id the runner sent in the
// untrusted data message, so the fake can bind its assessment to it —
// decodeAssessment rejects a missing or mismatched finding_id.
func requestFindingID(msgs []triageReqMsg) string {
	const marker = `"finding_id"`
	for _, m := range msgs {
		if m.Role != "user" || !strings.Contains(m.Content, "[FINDING — UNTRUSTED DATA]") {
			continue
		}
		i := strings.Index(m.Content, marker)
		if i < 0 {
			return ""
		}
		rest := m.Content[i+len(marker):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			return ""
		}
		rest = rest[j+1:]
		k := strings.Index(rest, `"`)
		if k < 0 {
			return ""
		}
		return rest[:k]
	}
	return ""
}

// injectFindingID sets finding_id on a scripted assessment reply, the way
// a real agent copies it from the input finding verbatim.
func injectFindingID(content, id string) string {
	var m map[string]any
	if id == "" || json.Unmarshal([]byte(content), &m) != nil {
		return content
	}
	if _, ok := m["verdict"]; !ok {
		return content
	}
	m["finding_id"] = id
	b, err := json.Marshal(m)
	if err != nil {
		return content
	}
	return string(b)
}

// fakeTriageLLM is a deterministic OpenAI-compatible endpoint: it answers
// each /chat/completions request with replies(callIndex) and records the
// requested model of every call. No real LLM is ever contacted.
func fakeTriageLLM(t *testing.T, replies func(call int) triageReply) (*httptest.Server, *[]string) {
	t.Helper()
	models := new([]string)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string         `json:"model"`
			Messages []triageReqMsg `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		*models = append(*models, req.Model)
		rep := replies(calls)
		calls++
		var msg map[string]any
		if len(rep.toolCalls) > 0 {
			msg = map[string]any{"role": "assistant", "tool_calls": rep.toolCalls}
		} else {
			msg = map[string]any{"role": "assistant", "content": injectFindingID(rep.content, requestFindingID(req.Messages))}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message":       msg,
				"finish_reason": "stop",
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, models
}

// cliFixtureRepo returns the minimal e2e product: one module, one package
// main, so every evidencetools session over it stays small enough for the
// observation size cap.
func cliFixtureRepo(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "internal", "testdata", "e2e-product"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p, "go.mod")); err != nil {
		t.Fatalf("e2e fixture missing: %v", err)
	}
	return p
}

func triageFinding(id, repo string) map[string]any {
	return map[string]any{
		"schema_version": "finding.v1",
		"finding_id":     id,
		"vulnerability":  map[string]any{"ids": []string{"CVE-2099-0001"}, "summary": "fixture advisory"},
		"component":      map[string]any{"name": "ghost", "package": "example.org/ghostpkg", "version": "v0.5.0", "ecosystem": "go"},
		"target":         map[string]any{"repository": repo},
		// scanner.severity is the compatibility transport's baseline source:
		// without it a decision package has no authoritative severity.
		"scanner": map[string]any{"severity": "high"},
	}
}

func writeFindings(t *testing.T, findings ...map[string]any) string {
	t.Helper()
	var b strings.Builder
	for _, f := range findings {
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// cliAssessmentDet cites the recorded deterministic-tool observation the
// agent is scripted to call: evidence kind det with the canonical
// det:<id> locator — a reproducible reference, never proof.
const cliAssessmentDet = `{
  "schema_version": "assessment.v3",
  "verdict": "NOT_EXPLOITABLE",
  "summary": "the declared vulnerable module is absent from the product snapshot",
  "claims": [
    {"id": "c1", "statement": "the product snapshot carries no vulnerable component", "basis": "INTERPRETED", "subject": "vulnerable component presence", "scope": "captured product snapshot", "decision_relevant": true, "evidence_refs": ["ev-1"]}
  ],
  "evidence": [
    {"id": "ev-1", "kind": "det", "locator": "det:det-0001"}
  ],
  "proposed_action": {"kind": "CLOSE", "instruction": "close the ticket as not exploitable", "rationale": "the recorded snapshot carries no vulnerable component", "scope": "captured product snapshot", "decisive_claim_ids": ["c1"], "reconsider_when": ["the vulnerable component appears in a captured snapshot"]}
}`

// cliAssessmentForeignAuthority returns a Product A verdict spelling —
// decodeAssessment rejects it, so the finding lands on the technical-error
// channel instead of producing a safe-looking package.
const cliAssessmentForeignAuthority = `{
  "schema_version": "assessment.v3",
  "verdict": "NOT_AFFECTED",
  "summary": "authoritative verdict spelled in Product A terms",
  "claims": []
}`

func staticReply(body string) func(int) triageReply {
	return func(int) triageReply { return triageReply{content: body} }
}

// detThenAssessment scripts turn 1: one allowlisted det call
// (get_product_snapshot), turn 2: the assessment JSON.
func detThenAssessment(assessment string) func(int) triageReply {
	return func(call int) triageReply {
		if call == 0 {
			return triageReply{toolCalls: []map[string]any{{
				"id": "call-1", "type": "function",
				"function": map[string]any{"name": "get_product_snapshot", "arguments": "{}"},
			}}}
		}
		return triageReply{content: assessment}
	}
}

func wantExit(t *testing.T, err error, code int) {
	t.Helper()
	var ee *cliExitError
	if !errors.As(err, &ee) || ee.code != code {
		t.Fatalf("runTriage error = %v, want exit code %d", err, code)
	}
}

func runDir(t *testing.T, out, findingID string) string {
	t.Helper()
	dir, err := triage.RunDirName(findingID)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(out, dir)
}

func assertFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected artifact %s: %v", path, err)
	}
	return data
}

func assertNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("unexpected artifact %s exists", path)
	}
}

func readDecision(t *testing.T, dir string) triage.DecisionPackage {
	t.Helper()
	var pkg triage.DecisionPackage
	if err := json.Unmarshal(assertFile(t, filepath.Join(dir, "decision.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	return pkg
}

// TestTriageCLIFlags covers the strict argument contract: every shape of
// malformed invocation exits 2 before any LLM traffic.
func TestTriageCLIFlags(t *testing.T) {
	srv, _ := fakeTriageLLM(t, staticReply(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("f-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "missing input", args: []string{"--out", out}},
		{name: "missing --out", args: []string{"--input", input}},
		{name: "unknown --fail-on", args: []string{"--input", input, "--out", out, "--fail-on", "block-everything"}},
		{name: "bad --det-tools", args: []string{"--input", input, "--out", out, "--det-tools", "sometimes"}},
		{name: "input and ticket", args: []string{"--input", input, "--ticket", input, "--out", out}},
		{name: "input and replay", args: []string{"--input", input, "--replay-run", out, "--out", out}},
		{name: "missing --llm-env file", args: []string{"--input", input, "--out", out, "--llm-env", filepath.Join(t.TempDir(), "no-such.env")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			triageEnv(t, srv.URL)
			wantExit(t, runTriage(tc.args), triage.ExitCodeError)
		})
	}
}

// TestTriageCLIE2EChain runs the full pipeline on the real fixture:
// --input finding.v1 → snapshot → scripted agent (one det call) →
// FactGate VALID det: reference → decision package → artifacts →
// offline --replay-run byte-identical decision.json.
func TestTriageCLIE2EChain(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("e2e-cli-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	dir := runDir(t, out, "e2e-cli-1")
	for _, name := range []string{
		"input.json", "snapshot.json", "stage0.json", "intake.json",
		"raw-agent.json", "assessment.json", "assessment.md",
		"decision.json", "decision.md", "fact-gate.json",
		"observation-archive.json",
		filepath.Join("audit", "events.jsonl"),
	} {
		assertFile(t, filepath.Join(dir, name))
	}
	// metrics.json lives at the batch root, not inside the run dir.
	assertFile(t, filepath.Join(out, "metrics.json"))

	var a triage.Assessment
	if err := json.Unmarshal(assertFile(t, filepath.Join(dir, "assessment.json")), &a); err != nil {
		t.Fatal(err)
	}
	if a.Verdict != triage.VerdictNotExploitable || a.FactValidation != triage.ValidationComplete {
		t.Fatalf("assessment: verdict=%s validation=%s", a.Verdict, a.FactValidation)
	}
	if a.FactValidationDetail == nil || len(a.FactValidationDetail.References) != 1 {
		t.Fatalf("fact_validation_detail missing: %+v", a.FactValidationDetail)
	}
	ref := a.FactValidationDetail.References[0]
	if ref.EvidenceID != "ev-1" || ref.Status != triage.FactValid || ref.Tool != "get_product_snapshot" {
		t.Fatalf("det: reference check = %+v, want VALID against the recorded observation", ref)
	}

	pkg := readDecision(t, dir)
	if pkg.SchemaVersion != triage.DecisionPackageSchemaVersion {
		t.Fatalf("decision schema_version = %q", pkg.SchemaVersion)
	}
	if pkg.Judgment.Verdict == "" || pkg.ProposedAction.Instruction == "" {
		t.Fatalf("the human axes are missing from the decision package: %+v", pkg)
	}
	// No verified falsifier exists on the compatibility transport: the
	// package can never dismiss, whatever the agent verdict says.
	if pkg.MachineDisposition.Recommendation == triage.RecommendationDismissed {
		t.Fatal("decision dismissed without a verified falsifier — auto-dismissal boundary violated")
	}
	if len(pkg.FalsifierProofs) != 0 {
		t.Fatalf("falsifier_proofs present without any verification run: %+v", pkg.FalsifierProofs)
	}

	// The audit trail carries the det tool_call event for the recorded
	// observation the assessment cited.
	audit := string(assertFile(t, filepath.Join(dir, "audit", "events.jsonl")))
	if !strings.Contains(audit, "get_product_snapshot") {
		t.Fatalf("audit trail missing the det tool call: %s", audit)
	}

	// --- offline replay: byte-identical decision.json ---
	outReplay := filepath.Join(t.TempDir(), "replay")
	if err := runTriage([]string{"--replay-run", dir, "--out", outReplay}); err != nil {
		t.Fatalf("--replay-run: %v", err)
	}
	entries, err := filepath.Glob(filepath.Join(outReplay, "*-replay-*"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("replay output dir = %v, err=%v", entries, err)
	}
	replayed := assertFile(t, filepath.Join(entries[0], "decision.json"))
	source := assertFile(t, filepath.Join(dir, "decision.json"))
	if string(replayed) != string(source) {
		t.Fatal("replayed decision.json differs byte-wise from the source report")
	}
}

// TestTriageCLIPrintsActionPackageSummary: a completed `triage` announces
// the human action package, not the investigation artifacts. The single
// stdout line names the finding, the proposed action, the derived support,
// the machine disposition and the decision.md path; assessment.json is
// never presented as the result.
func TestTriageCLIPrintsActionPackageSummary(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("summary-cli-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runTriage([]string{"--input", input, "--out", out})
	})
	if runErr != nil {
		t.Fatalf("runTriage: %v", runErr)
	}
	dir := runDir(t, out, "summary-cli-1")
	pkg := readDecision(t, dir)
	line := strings.TrimSpace(stdout)
	if line == "" {
		t.Fatal("a completed triage printed no primary result")
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("the primary result is not one concise line: %q", line)
	}
	decisionPath := filepath.Join(dir, "decision.md")
	assertFile(t, decisionPath)
	for _, want := range []string{
		"summary-cli-1",
		"action=" + string(pkg.ProposedAction.Kind),
		"support=" + string(pkg.Support.Level),
		"machine=" + string(pkg.MachineDisposition.Recommendation),
		filepath.Join("summary-cli-1", "decision.md"),
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("primary result missing %q: %q", want, line)
		}
	}
	for _, unwanted := range []string{"assessment=", "verdict=", "fact_validation="} {
		if strings.Contains(line, unwanted) {
			t.Fatalf("primary result still points at the investigation artifact (%q): %q", unwanted, line)
		}
	}
}

// TestTriageCLIRecordDecision: a person records Accept/Reject against the
// exact delivered run with no --out, model credentials or network call.
// The command prints the recorded decision and the immutable record path,
// never a machine-safe result, and leaves decision.json, decision.md, VEX,
// policy/metrics and the assessment bytes unchanged.
func TestTriageCLIRecordDecision(t *testing.T) {
	srv, models := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("record-cli-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out, "--vex-projection"}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}
	dir := runDir(t, out, "record-cli-1")
	pkg, err := triage.ValidateDecisionPackageJSON(assertFile(t, filepath.Join(dir, "decision.json")))
	if err != nil {
		t.Fatalf("recorded decision.json: %v", err)
	}

	protected := map[string][]byte{}
	for _, path := range []string{
		filepath.Join(dir, "decision.json"),
		filepath.Join(dir, "decision.md"),
		filepath.Join(dir, "assessment.json"),
		filepath.Join(dir, "fact-gate.json"),
		filepath.Join(dir, "vex.json"),
		filepath.Join(out, "metrics.json"),
	} {
		data, rerr := os.ReadFile(path)
		if rerr == nil {
			protected[path] = data
		} else if !os.IsNotExist(rerr) {
			t.Fatalf("read %s: %v", path, rerr)
		}
	}
	card := string(assertFile(t, filepath.Join(dir, "decision.md")))
	for _, want := range []string{"--record-decision", "--decision accept", "--decision reject"} {
		if !strings.Contains(card, want) {
			t.Fatalf("decision.md lacks the concrete record command %q", want)
		}
	}

	callsBefore := len(*models)
	// Record mode needs no model at all: no LLM_* environment is set.
	for _, k := range []string{
		"LLM_ENABLED", "LLM_BASE_URL", "LLM_API_KEY",
		"LLM_ANALYZE_MODEL", "LLM_BUILD_MODEL", "LLM_MAX_TOKENS",
	} {
		t.Setenv(k, "")
	}
	record := func(args ...string) (string, error) {
		var runErr error
		stdout := captureStdout(t, func() { runErr = runTriage(args) })
		return stdout, runErr
	}

	stdout, err := record("--record-decision", dir, "--decision", "accept", "--actor", "alice", "--reason", "reviewed the captured build graph")
	if err != nil {
		t.Fatalf("record accept: %v", err)
	}
	line := strings.TrimSpace(stdout)
	if line == "" || strings.Contains(line, "\n") {
		t.Fatalf("record mode did not print one decision line: %q", stdout)
	}
	for _, want := range []string{"record-cli-1", "decision=ACCEPT", "record=", "human-decisions"} {
		if !strings.Contains(line, want) {
			t.Fatalf("record output lacks %q: %q", want, line)
		}
	}
	for _, unwanted := range []string{"machine=", "action=", "support=", "verdict="} {
		if strings.Contains(line, unwanted) {
			t.Fatalf("record output presents a machine result (%q): %q", unwanted, line)
		}
	}
	recordPath := strings.TrimSpace(line[strings.Index(line, "record=")+len("record="):])
	if _, serr := os.Stat(recordPath); serr != nil {
		t.Fatalf("printed record path does not exist: %v", serr)
	}
	if len(*models) != callsBefore {
		t.Fatalf("record mode performed %d model call(s)", len(*models)-callsBefore)
	}
	history, err := triage.ReadHumanDecisions(dir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions: %v", err)
	}
	if len(history) != 1 || history[0].Decision != triage.HumanDecisionAccept || history[0].Actor != "alice" {
		t.Fatalf("accept history = %+v", history)
	}

	stdout, err = record("--record-decision", dir, "--decision", "reject", "--actor", "bob", "--reason", "deployment evidence is still missing")
	if err != nil {
		t.Fatalf("record reject: %v", err)
	}
	if line := strings.TrimSpace(stdout); !strings.Contains(line, "decision=REJECT") {
		t.Fatalf("reject output = %q", line)
	}
	history, err = triage.ReadHumanDecisions(dir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions after reject: %v", err)
	}
	if len(history) != 2 || history[1].Decision != triage.HumanDecisionReject || history[1].Actor != "bob" {
		t.Fatalf("accept+reject history = %+v", history)
	}
	if len(*models) != callsBefore {
		t.Fatalf("reject mode performed a model call")
	}

	for path, before := range protected {
		if after, rerr := os.ReadFile(path); rerr != nil || string(after) != string(before) {
			t.Fatalf("%s changed after recording human decisions: err=%v", path, rerr)
		}
	}

	missing := t.TempDir()
	for name, args := range map[string][]string{
		"unknown decision":      {"--record-decision", dir, "--decision", "maybe", "--actor", "alice", "--reason", "reviewed"},
		"blank actor":           {"--record-decision", dir, "--decision", "accept", "--actor", "   ", "--reason", "reviewed"},
		"input is exclusive":    {"--record-decision", dir, "--decision", "accept", "--actor", "alice", "--reason", "reviewed", "--input", input},
		"out is unrelated":      {"--record-decision", dir, "--decision", "accept", "--actor", "alice", "--reason", "reviewed", "--out", out},
		"decision needs record": {"--input", input, "--out", out, "--decision", "accept", "--actor", "alice", "--reason", "reviewed"},
		"missing package":       {"--record-decision", missing, "--decision", "accept", "--actor", "alice", "--reason", "reviewed"},
	} {
		t.Run(name, func(t *testing.T) {
			wantExit(t, runTriage(args), triage.ExitCodeError)
		})
	}
	history, err = triage.ReadHumanDecisions(dir, pkg)
	if err != nil {
		t.Fatalf("ReadHumanDecisions after rejected invocations: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("rejected invocations changed history: %+v", history)
	}
}

// TestTriageCLIPolicyFailOn: --fail-on unchanged turns an UNCHANGED
// decision into exit 1 while the package itself stays byte-identical.
func TestTriageCLIPolicyFailOn(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("policy-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	wantExit(t, runTriage([]string{
		"--input", input, "--out", out, "--fail-on", "unchanged",
	}), triage.ExitCodePolicy)

	pkg := readDecision(t, runDir(t, out, "policy-1"))
	if pkg.MachineDisposition.Recommendation != triage.RecommendationUnchanged {
		t.Fatalf("recommendation = %s, want UNCHANGED under the unchanged threshold", pkg.MachineDisposition.Recommendation)
	}
}

// TestTriageCLITechnicalInput: malformed input never reaches the agent —
// the parse failure is a technical error (exit 2), not an empty batch.
func TestTriageCLITechnicalInput(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(bad, []byte(`{"schema_version":"finding.v2","finding_id":1,`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	srv, _ := fakeTriageLLM(t, staticReply(cliAssessmentDet))
	triageEnv(t, srv.URL)
	wantExit(t, runTriage([]string{"--input", bad, "--out", out}), triage.ExitCodeError)
}

// TestTriageCLIForeignAuthority: a Product A verdict spelling in the agent
// reply is rejected at decode — the run lands on the technical-error
// channel (exit 2) with error.json, never a safe-looking package.
func TestTriageCLIForeignAuthority(t *testing.T) {
	srv, _ := fakeTriageLLM(t, staticReply(cliAssessmentForeignAuthority))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("foreign-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	wantExit(t, runTriage([]string{"--input", input, "--out", out}), triage.ExitCodeError)

	dir := runDir(t, out, "foreign-1")
	assertFile(t, filepath.Join(dir, "error.json"))
	assertNoFile(t, filepath.Join(dir, "decision.json"))
}

// TestTriageCLITamperedReplay: a report whose stored decision no longer
// matches the recomposed package is a provenance failure — replay fails
// closed (exit 2), never re-renders the tampered bytes. The tampered card
// is self-consistent, so the failure comes from the machine-admissibility
// comparison, not from Markdown byte drift.
func TestTriageCLITamperedReplay(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("tamper-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}
	dir := runDir(t, out, "tamper-1")

	decPath := filepath.Join(dir, "decision.json")
	var pkg triage.DecisionPackage
	if err := json.Unmarshal(assertFile(t, decPath), &pkg); err != nil {
		t.Fatal(err)
	}
	pkg.MachineDisposition.Rationale.Summary = "rewritten after the run"
	tampered, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "decision.md"), triage.RenderDecisionMarkdown(pkg), 0o644); err != nil {
		t.Fatal(err)
	}

	wantExit(t, runTriage([]string{
		"--replay-run", dir, "--out", filepath.Join(t.TempDir(), "replay"),
	}), triage.ExitCodeError)
}

// TestTriageCLIVexProjection: the projection stays default-off and
// non-authoritative — an UNCHANGED package can never yield a
// not_affected statement, so the boundary records a denial and writes no
// vex.json; with the flag off the audit stays silent.
func TestTriageCLIVexProjection(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)

	// flag off: no vex.json, no audit event at all.
	input := writeFindings(t, triageFinding("vex-off", repo))
	out := filepath.Join(t.TempDir(), "out")
	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}
	dir := runDir(t, out, "vex-off")
	assertFile(t, filepath.Join(dir, "decision.json"))
	assertNoFile(t, filepath.Join(dir, "vex.json"))
	audit := string(assertFile(t, filepath.Join(dir, "audit", "events.jsonl")))
	if strings.Contains(audit, "vex_projection") {
		t.Fatalf("audit must stay silent on the projection when the flag is off: %s", audit)
	}

	// flag on: UNCHANGED is inadmissible for not_affected → denial audit,
	// no vex.json, exit code unchanged.
	input2 := writeFindings(t, triageFinding("vex-on", repo))
	out2 := filepath.Join(t.TempDir(), "out")
	if err := runTriage([]string{"--input", input2, "--out", out2, "--vex-projection"}); err != nil {
		t.Fatalf("runTriage --vex-projection: %v", err)
	}
	dir2 := runDir(t, out2, "vex-on")
	pkg := readDecision(t, dir2)
	if pkg.MachineDisposition.Recommendation != triage.RecommendationUnchanged {
		t.Fatalf("recommendation = %s, want UNCHANGED on the compatibility transport", pkg.MachineDisposition.Recommendation)
	}
	assertNoFile(t, filepath.Join(dir2, "vex.json"))
	audit2 := string(assertFile(t, filepath.Join(dir2, "audit", "events.jsonl")))
	if !strings.Contains(audit2, `"type":"vex_projection"`) || !strings.Contains(audit2, `"status":"denied"`) {
		t.Fatalf("audit must record the denied projection: %s", audit2)
	}
}

// TestAdmissionCheckGateSemantics pins the admission-check exit contract:
// the falsifier-proof final gate is the enforcement surface whose exit
// code fails a run when a cited mandatory condition lacks a VERIFIED
// proof. CheckPass is not fatal; a falsifier check whose status is merely
// UNVERIFIED (recorded limitation, not forged/malformed evidence) is not
// fatal either; every other non-PASS outcome — including UNVERIFIED on a
// different check and any falsifier check whose status is CheckFail — is
// fatal and must produce a non-zero run exit. This is distinct from the
// offline izyan-heldout-gate reporter's pass/fail summary, which never
// blocks case admission.
func TestAdmissionCheckGateSemantics(t *testing.T) {
	cases := []struct {
		name    string
		checkID string
		status  triage.CheckStatus
		fatal   bool
	}{
		{"pass is never fatal", triage.CheckIDFalsifierProof, triage.CheckPass, false},
		{"falsifier UNVERIFIED is a recorded limitation", triage.CheckIDFalsifierProof, triage.CheckUnverified, false},
		{"falsifier CONFLICTING is fatal (forged/malformed proof)", triage.CheckIDFalsifierProof, triage.CheckConflicting, true},
		{"falsifier ERROR is fatal", triage.CheckIDFalsifierProof, triage.CheckError, true},
		{"non-falsifier UNVERIFIED is fatal", triage.CheckIDRiskPolicy, triage.CheckUnverified, true},
		{"non-falsifier INVALID is fatal", triage.CheckIDPackageStability, triage.CheckInvalid, true},
	}
	for _, tc := range cases {
		if got := fatalFinalGateResult(tc.checkID, tc.status); got != tc.fatal {
			t.Fatalf("%s: fatalFinalGateResult(%q, %q) = %v, want %v", tc.name, tc.checkID, tc.status, got, tc.fatal)
		}
	}
}

// TestTriageCLIWithoutBaselineDeliversHumanPackage covers every live mode:
// finding input, generic ticket input and replay. None may require an
// external control result, and the batch metrics artifact is observational
// only (triage-metrics.v3, no false-safe claim). The obsolete live
// --baseline flag is refused with a pointer to offline evaluation.
func TestTriageCLIWithoutBaselineDeliversHumanPackage(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("no-baseline-live-1", repo))
	out := filepath.Join(t.TempDir(), "out")

	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("live finding input without a baseline: %v", err)
	}
	dir := runDir(t, out, "no-baseline-live-1")
	pkg := readDecision(t, dir)
	if pkg.ProposedAction.Kind == "" || pkg.ProposedAction.Instruction == "" {
		t.Fatalf("human action package missing: %+v", pkg.ProposedAction)
	}

	var metricsDoc struct {
		SchemaVersion string         `json:"schema_version"`
		Metrics       map[string]any `json:"metrics"`
	}
	if err := json.Unmarshal(assertFile(t, filepath.Join(out, "metrics.json")), &metricsDoc); err != nil {
		t.Fatalf("metrics.json: %v", err)
	}
	if metricsDoc.SchemaVersion != triage.MetricsSchemaVersion {
		t.Fatalf("metrics schema = %q, want %q", metricsDoc.SchemaVersion, triage.MetricsSchemaVersion)
	}
	for _, removed := range []string{"false_safe_count", "false_safe_verified", "false_safe_violation", "unverified_reduction_count"} {
		if _, ok := metricsDoc.Metrics[removed]; ok {
			t.Fatalf("production metrics still claim %q: %v", removed, metricsDoc.Metrics)
		}
	}
	for _, want := range []string{"human_action_kinds", "support_levels", "machine_recommendations", "machine_automation"} {
		if _, ok := metricsDoc.Metrics[want]; !ok {
			t.Fatalf("production metrics missing %q: %v", want, metricsDoc.Metrics)
		}
	}

	// The removed live flag cannot silently degrade into "flag not
	// defined": it names the offline evaluator.
	err := runTriage([]string{"--input", input, "--out", filepath.Join(t.TempDir(), "obsolete"), "--baseline", "baselines.json"})
	wantExit(t, err, triage.ExitCodeError)
	if !strings.Contains(err.Error(), "eval triage") {
		t.Fatalf("obsolete --baseline error does not point to offline evaluation: %v", err)
	}

	// --- generic ticket input: the same human package with no external
	// control anywhere in the run configuration. ---
	ticketRepo := t.TempDir()
	if err := os.WriteFile(filepath.Join(ticketRepo, "go.mod"), []byte("module example.com/ticketprod\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ticketRepo, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	siteConfig, err := json.Marshal(map[string]any{
		"schema_version": "triage-site.v1",
		"sources": map[string]any{
			"repositories": []map[string]any{{
				"id": "ticketprod", "kind": "local", "root": ticketRepo, "ecosystem": "go",
			}},
			"advisory": map[string]any{"priority": []string{"ticket"}, "freeze": true},
		},
		"resolution": map[string]any{"max_candidates": 16, "max_feedback_passes": 2},
		"policy":     map[string]any{"on_drift": "error"},
		"budgets":    map[string]any{"max_advisory_bytes": 1 << 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	sitePath := filepath.Join(t.TempDir(), "triage-site.json")
	if err := os.WriteFile(sitePath, siteConfig, 0o644); err != nil {
		t.Fatal(err)
	}
	ticketPath := filepath.Join(t.TempDir(), "ticket.txt")
	if err := os.WriteFile(ticketPath, []byte("Vulnerability: CVE-2099-0001\nComponent: ticketprod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ticketReplies := func(call int) triageReply {
		if call == 0 {
			return triageReply{content: `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"component":"ticketprod","package":"example.com/ticketprod","severity":"high","summary":"fixture intake"}`}
		}
		return detThenAssessment(cliAssessmentDet)(call - 1)
	}
	ticketSrv, _ := fakeTriageLLM(t, ticketReplies)
	triageEnv(t, ticketSrv.URL)
	ticketOut := filepath.Join(t.TempDir(), "out")
	if err := runTriage([]string{"--ticket", ticketPath, "--config", sitePath, "--out", ticketOut}); err != nil {
		t.Fatalf("ticket input without a baseline: %v", err)
	}
	decisions, err := filepath.Glob(filepath.Join(ticketOut, "*", "decision.json"))
	if err != nil || len(decisions) != 1 {
		t.Fatalf("ticket decision packages = %v, err=%v", decisions, err)
	}
	ticketPkg := readDecision(t, filepath.Dir(decisions[0]))
	if ticketPkg.ProposedAction.Instruction == "" {
		t.Fatalf("ticket human action package missing: %+v", ticketPkg.ProposedAction)
	}

	// --- replay: no model, no baseline, same recorded human package. ---
	replayEnv := filepath.Join(t.TempDir(), "replay")
	if err := runTriage([]string{"--replay-run", dir, "--out", replayEnv}); err != nil {
		t.Fatalf("replay without a baseline: %v", err)
	}
	replayed, err := filepath.Glob(filepath.Join(replayEnv, "*-replay-*"))
	if err != nil || len(replayed) != 1 {
		t.Fatalf("replay output = %v, err=%v", replayed, err)
	}
	if got := assertFile(t, filepath.Join(replayed[0], "decision.json")); string(got) != string(assertFile(t, filepath.Join(dir, "decision.json"))) {
		t.Fatal("replayed decision.json differs from the source")
	}
}

// TestTriageCLIInvestigationInputs: --investigation-inputs captures a
// supplied advisory/fix set for both transports. The exact bytes are
// archived by digest, prompt-input.v1 is persisted before the agent loop,
// and the decision scope binds the records actually considered.
func TestTriageCLIInvestigationInputs(t *testing.T) {
	recordA := []byte(`{"id":"CVE-2099-0002","summary":"supplied captured advisory","aliases":["GHSA-cli-0002"]}`)
	fixA := []byte("--- a/probe.go\n+++ b/probe.go\n+supplied fix\n")
	manifestDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(manifestDir, "advisory.json"), recordA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifestDir, "fix.diff"), fixA, 0o644); err != nil {
		t.Fatal(err)
	}
	recordSHA, fixSHA := sha256TestHex(recordA), sha256TestHex(fixA)
	manifest := map[string]any{
		"schema_version": "investigation-inputs.v1",
		"records": []any{map[string]any{
			"record_id": "CVE-2099-0002", "aliases": []string{"GHSA-cli-0002"},
			"path": "advisory.json", "sha256": recordSHA, "source": "operator-freeze",
		}},
		"fixes": []any{map[string]any{
			"record_id": "CVE-2099-0002", "record_sha256": recordSHA,
			"locator": "https://example.test/fix/cli.diff", "outcome": "captured",
			"path": "fix.diff", "sha256": fixSHA,
		}},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDir, "investigation-inputs.json")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("finding transport", func(t *testing.T) {
		srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
		repo := cliFixtureRepo(t)
		input := writeFindings(t, triageFinding("investigation-inputs-1", repo))
		out := filepath.Join(t.TempDir(), "out")
		triageEnv(t, srv.URL)
		if err := runTriage([]string{"--input", input, "--out", out, "--investigation-inputs", manifestPath}); err != nil {
			t.Fatalf("finding transport with captured inputs: %v", err)
		}
		dir := runDir(t, out, "investigation-inputs-1")
		assertFile(t, filepath.Join(dir, "prompt-input.json"))
		projection := assertFile(t, filepath.Join(dir, "investigation-inputs.json"))
		if !strings.Contains(string(projection), "CVE-2099-0002") || !strings.Contains(string(projection), "GHSA-cli-0002") {
			t.Fatalf("investigation projection does not carry the supplied identity: %s", projection)
		}
		if got := assertFile(t, filepath.Join(dir, "materials", recordSHA)); string(got) != string(recordA) {
			t.Fatalf("archived record bytes differ from the supplied bytes")
		}
		if got := assertFile(t, filepath.Join(dir, "materials", fixSHA)); string(got) != string(fixA) {
			t.Fatalf("archived fix bytes differ from the supplied bytes")
		}
		pkg := readDecision(t, dir)
		found := false
		for _, rec := range pkg.Scope.Records {
			if rec.ID == "CVE-2099-0002" && rec.SHA256 == recordSHA {
				found = true
			}
		}
		if !found {
			t.Fatalf("decision scope does not bind the supplied record: %+v", pkg.Scope.Records)
		}
	})

	t.Run("ticket transport", func(t *testing.T) {
		ticketRepo := t.TempDir()
		if err := os.WriteFile(filepath.Join(ticketRepo, "go.mod"), []byte("module example.com/ticketprod\n\ngo 1.23\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ticketRepo, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		siteConfig, err := json.Marshal(map[string]any{
			"schema_version": "triage-site.v1",
			"sources": map[string]any{
				"repositories": []map[string]any{{"id": "ticketprod", "kind": "local", "root": ticketRepo, "ecosystem": "go"}},
				"advisory":     map[string]any{"priority": []string{"ticket"}, "freeze": true},
			},
			"resolution": map[string]any{"max_candidates": 16, "max_feedback_passes": 2},
			"policy":     map[string]any{"on_drift": "error"},
			"budgets":    map[string]any{"max_advisory_bytes": 1 << 20},
		})
		if err != nil {
			t.Fatal(err)
		}
		sitePath := filepath.Join(t.TempDir(), "triage-site.json")
		if err := os.WriteFile(sitePath, siteConfig, 0o644); err != nil {
			t.Fatal(err)
		}
		ticketPath := filepath.Join(t.TempDir(), "ticket.txt")
		if err := os.WriteFile(ticketPath, []byte("Vulnerability: CVE-2099-0001\nComponent: ticketprod\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		replies := func(call int) triageReply {
			if call == 0 {
				return triageReply{content: `{"schema_version":"intake-proposal.v1","vulnerability_ids":["CVE-2099-0001"],"component":"ticketprod","package":"example.com/ticketprod","severity":"high","summary":"fixture intake"}`}
			}
			return detThenAssessment(cliAssessmentDet)(call - 1)
		}
		srv, _ := fakeTriageLLM(t, replies)
		triageEnv(t, srv.URL)
		out := filepath.Join(t.TempDir(), "out")
		if err := runTriage([]string{"--ticket", ticketPath, "--config", sitePath, "--out", out, "--investigation-inputs", manifestPath}); err != nil {
			t.Fatalf("ticket transport with captured inputs: %v", err)
		}
		matches, err := filepath.Glob(filepath.Join(out, "*", "investigation-inputs.json"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("ticket investigation projection = %v, err=%v", matches, err)
		}
		runPath := filepath.Dir(matches[0])
		assertFile(t, filepath.Join(runPath, "prompt-input.json"))
		projection := assertFile(t, matches[0])
		for _, want := range []string{"CVE-2099-0001", "CVE-2099-0002"} {
			if !strings.Contains(string(projection), want) {
				t.Fatalf("Stage 0 captured set does not include %s: %s", want, projection)
			}
		}
		// The selected frozen document is archived by its own digest; the
		// complete bytes are readable without the freeze directory.
		var stageDoc struct {
			Advisory struct {
				Path   string `json:"path"`
				SHA256 string `json:"sha256"`
				Size   int64  `json:"size"`
			} `json:"advisory"`
		}
		if err := json.Unmarshal(assertFile(t, filepath.Join(runPath, "stage0.json")), &stageDoc); err != nil {
			t.Fatal(err)
		}
		frozen := assertFile(t, stageDoc.Advisory.Path)
		if got := sha256TestHex(frozen); got != stageDoc.Advisory.SHA256 {
			t.Fatalf("frozen advisory drifted: %s != %s", got, stageDoc.Advisory.SHA256)
		}
		if got := assertFile(t, filepath.Join(runPath, "materials", stageDoc.Advisory.SHA256)); string(got) != string(frozen) {
			t.Fatal("Stage 0 frozen document was not archived byte-identically")
		}
	})

	t.Run("invalid manifest", func(t *testing.T) {
		input := writeFindings(t, triageFinding("investigation-inputs-2", cliFixtureRepo(t)))
		out := filepath.Join(t.TempDir(), "out")
		err := runTriage([]string{"--input", input, "--out", out, "--investigation-inputs", filepath.Join(t.TempDir(), "missing.json")})
		wantExit(t, err, triage.ExitCodeError)
		if !strings.Contains(err.Error(), "--investigation-inputs") {
			t.Fatalf("invalid manifest error does not name the flag: %v", err)
		}
	})
}

// TestCapturedResearchToolsNeverFetch drives the real CLI session with a
// captured record/fix set: every verified captured record answers advisory
// research (not only the record the finding selected), an id or locator
// outside that set is UNSUPPORTED, and repository execution stays
// unavailable. A tripwire DefaultTransport proves no captured lookup fell
// back to the network — the run is offline by construction, not by luck.
func TestCapturedResearchToolsNeverFetch(t *testing.T) {
	recordA := []byte(`{"id":"CVE-2099-0002","summary":"captured advisory A","aliases":["GHSA-cap-0002"],"references":[{"type":"FIX","url":"https://example.test/fix/captured.diff"}]}`)
	recordB := []byte(`{"id":"CVE-2099-0003","summary":"captured advisory B"}`)
	fixA := []byte("--- a/probe.go\n+++ b/probe.go\n+supplied fix\n")
	manifestDir := t.TempDir()
	for name, data := range map[string][]byte{"a.json": recordA, "b.json": recordB, "a.diff": fixA} {
		if err := os.WriteFile(filepath.Join(manifestDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := map[string]any{
		"schema_version": "investigation-inputs.v1",
		"records": []any{
			map[string]any{"record_id": "CVE-2099-0002", "aliases": []string{"GHSA-cap-0002"},
				"path": "a.json", "sha256": sha256TestHex(recordA), "source": "operator-freeze"},
			map[string]any{"record_id": "CVE-2099-0003",
				"path": "b.json", "sha256": sha256TestHex(recordB), "source": "api"},
		},
		"fixes": []any{
			map[string]any{"record_id": "CVE-2099-0002", "record_sha256": sha256TestHex(recordA),
				"locator": "https://example.test/fix/captured.diff", "outcome": "captured",
				"path": "a.diff", "sha256": sha256TestHex(fixA)},
			map[string]any{"record_id": "CVE-2099-0003", "record_sha256": sha256TestHex(recordB),
				"locator": "https://example.test/fix/declared-missing.diff", "outcome": "missing"},
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDir, "investigation-inputs.json")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	replies := func(call int) triageReply {
		if call > 0 {
			return triageReply{content: cliAssessmentDet}
		}
		toolCall := func(id, name, args string) map[string]any {
			return map[string]any{"id": id, "type": "function",
				"function": map[string]any{"name": name, "arguments": args}}
		}
		return triageReply{toolCalls: []map[string]any{
			toolCall("call-1", "get_product_snapshot", `{}`),
			toolCall("call-2", "get_vulnerability", `{}`),
			toolCall("call-3", "get_advisory", `{"id":"CVE-2099-0002"}`),
			toolCall("call-4", "get_advisory", `{"id":"GHSA-absent-0001"}`),
			toolCall("call-5", "get_fix_diff", `{"url":"https://example.test/fix/captured.diff"}`),
			toolCall("call-6", "get_fix_diff", `{"url":"https://example.test/fix/declared-missing.diff"}`),
			toolCall("call-7", "get_fix_diff", `{"url":"https://example.test/fix/unknown.diff"}`),
		}}
	}
	srv, _ := fakeTriageLLM(t, replies)
	triageEnv(t, srv.URL)
	input := writeFindings(t, triageFinding("captured-research-1", cliFixtureRepo(t)))
	out := filepath.Join(t.TempDir(), "out")

	prevTransport := http.DefaultTransport
	wire := &tripwireTransport{}
	http.DefaultTransport = wire
	t.Cleanup(func() { http.DefaultTransport = prevTransport })

	if err := runTriage([]string{"--input", input, "--out", out, "--investigation-inputs", manifestPath}); err != nil {
		if data, rerr := os.ReadFile(filepath.Join(runDir(t, out, "captured-research-1"), "error.json")); rerr == nil {
			t.Fatalf("runTriage: %v\nerror.json: %s", err, data)
		}
		t.Fatalf("runTriage: %v", err)
	}
	dir := runDir(t, out, "captured-research-1")

	var doc triage.RawAgentDocument
	if err := json.Unmarshal(assertFile(t, filepath.Join(dir, "raw-agent.json")), &doc); err != nil {
		t.Fatal(err)
	}
	var statuses []string
	for _, m := range doc.Messages {
		if m.Role != "tool" {
			continue
		}
		var obs triage.ToolObservation
		if err := json.Unmarshal([]byte(m.Content), &obs); err != nil {
			t.Fatalf("tool message %q: %v", m.ToolCallID, err)
		}
		statuses = append(statuses, obs.Tool+"="+obs.Status)
	}
	want := []string{
		"get_product_snapshot=OK",
		"get_vulnerability=UNSUPPORTED",
		"get_advisory=OK",
		"get_advisory=UNSUPPORTED",
		"get_fix_diff=OK",
		"get_fix_diff=UNSUPPORTED",
		"get_fix_diff=UNSUPPORTED",
	}
	if strings.Join(statuses, ",") != strings.Join(want, ",") {
		t.Fatalf("captured research statuses = %v, want %v", statuses, want)
	}
	if hits := wire.hits.Load(); hits != 0 {
		t.Fatalf("captured research issued %d network request(s); the configured set must be the only source", hits)
	}

	// The advertised surface is the session's, and it includes the research
	// tools the captured set opened.
	var prompt triage.PromptInput
	promptBytes := assertFile(t, filepath.Join(dir, triage.PromptInputArtifactName))
	if err := json.Unmarshal(promptBytes, &prompt); err != nil {
		t.Fatal(err)
	}
	advertised := map[string]bool{}
	for _, def := range prompt.Tools {
		advertised[def.Function.Name] = true
	}
	for _, name := range []string{"get_vulnerability", "get_advisory", "get_fix_references", "get_fix_diff"} {
		if !advertised[name] {
			t.Fatalf("captured research tool %q is not advertised: %v", name, advertised)
		}
	}
	for _, name := range []string{"run_build", "run_tests"} {
		if advertised[name] {
			t.Fatalf("repository execution %q is advertised without AllowExec", name)
		}
	}

	// Replay verifies the recorded surface, not today's permissions: the
	// saved run advertised the research tools its captured set opened, and
	// a replay session (which holds no captured source at all) must neither
	// re-admit nor remove one. The replayed prompt-input must be the saved
	// bytes verbatim.
	replayOut := filepath.Join(t.TempDir(), "replay")
	if err := runTriage([]string{"--replay-run", dir, "--out", replayOut}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	replayed, err := filepath.Glob(filepath.Join(replayOut, "*-replay-*"))
	if err != nil || len(replayed) != 1 {
		t.Fatalf("replay output = %v, err=%v", replayed, err)
	}
	if got := assertFile(t, filepath.Join(replayed[0], triage.PromptInputArtifactName)); string(got) != string(promptBytes) {
		t.Fatal("replay did not preserve the recorded prompt/tool surface verbatim")
	}
}

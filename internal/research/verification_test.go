package research

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/toolchain"
)

// verificationPlanFixture builds a plan that satisfies
// ValidateVerificationPlan: a recognized falsifier, bound condition id
// and n checks on the given tool with object arguments.
func verificationPlanFixture(n int, tool string) VerificationPlan {
	plan := VerificationPlan{Falsifier: FalsifierProposal{
		Kind: domain.FalsifierPackageAbsent, ConditionID: "cond-1",
		Module: "example.com/dep", Package: "example.com/dep/pkg",
		Statement: "the required package is absent", Scope: "product build closure",
	}}
	for i := range n {
		plan.Checks = append(plan.Checks, VerificationRequest{
			ID: "check-" + string(rune('a'+i)), Tool: tool,
			Arguments: json.RawMessage(`{}`), Purpose: "probe", ConditionID: "cond-1",
		})
	}
	return plan
}

func completeObs(tool string) *evidencetools.Observation {
	return &evidencetools.Observation{
		ID: "OBS-X", Tool: tool, Fact: "closed check complete",
		Scope: "closed scope", Completeness: evidencetools.CompletenessComplete,
		ToolStatus:   evidencetools.StatusOK,
		EvidenceRefs: []string{"sha256:abc"},
		ScopeDetails: &evidencetools.ScopeDetails{
			SnapshotHash: "h", CoverageRule: "closed",
			BuildContext: &evidencetools.BuildContext{GOOS: "linux"},
		},
	}
}

// TestVerificationPlanRunComplete: every declared check dispatches in
// order and COMPLETE/OK observations stay verbatim on the trace.
func TestVerificationPlanRunComplete(t *testing.T) {
	var tools []string
	call := func(_ context.Context, tool string, _ json.RawMessage) (*evidencetools.Observation, error) {
		tools = append(tools, tool)
		return completeObs(tool), nil
	}
	plan := verificationPlanFixture(2, "read_source")
	trace, err := RunVerificationPlan(context.Background(), call, plan, maxVerificationChecks)
	if err != nil {
		t.Fatal(err)
	}
	if !trace.Complete || len(trace.Limitations) != 0 {
		t.Fatalf("complete=%v limitations=%v", trace.Complete, trace.Limitations)
	}
	if len(trace.Observations) != 2 || len(trace.Requests) != 2 {
		t.Fatalf("obs=%d reqs=%d", len(trace.Observations), len(trace.Requests))
	}
	for i, o := range trace.Observations {
		if o.ID != "OBS-X" || o.Tool != tools[i] || o.ScopeDetails == nil ||
			o.ScopeDetails.SnapshotHash != "h" || len(o.EvidenceRefs) != 1 {
			t.Fatalf("observation %d lost session details: %+v", i, o)
		}
	}
}

// TestVerificationPlanRunPartialEmpty: an OK+PARTIAL empty observation
// is preserved verbatim — never promoted — and marks the trace
// incomplete with a named limitation.
func TestVerificationPlanRunPartialEmpty(t *testing.T) {
	partial := &evidencetools.Observation{
		ID: "OBS-P", Tool: "find_callers", Fact: "no callers found in product scope",
		Scope: "product packages only", Completeness: evidencetools.CompletenessPartial,
		ToolStatus:  evidencetools.StatusOK,
		Limitations: []string{"product scope only; dependency-internal callers not covered"},
	}
	call := func(_ context.Context, _ string, _ json.RawMessage) (*evidencetools.Observation, error) {
		return partial, nil
	}
	trace, err := RunVerificationPlan(context.Background(), call, verificationPlanFixture(1, "find_callers"), maxVerificationChecks)
	if err != nil {
		t.Fatal(err)
	}
	if trace.Complete {
		t.Fatal("PARTIAL observation must not yield a complete trace")
	}
	got := trace.Observations[0]
	if got != partial || got.Data != nil || got.Completeness != evidencetools.CompletenessPartial ||
		len(got.Limitations) != 1 {
		t.Fatalf("partial observation mutated or promoted: %+v", got)
	}
	if len(trace.Limitations) != 1 || !strings.Contains(trace.Limitations[0], "check-a") ||
		!strings.Contains(trace.Limitations[0], "PARTIAL") {
		t.Fatalf("limitations=%v", trace.Limitations)
	}
}

// TestVerificationPlanRunDegradedStatuses: ERROR, TIMEOUT and
// UNSUPPORTED observations stay on the trace verbatim and each is
// named as a limitation.
func TestVerificationPlanRunDegradedStatuses(t *testing.T) {
	statuses := []evidencetools.ToolStatus{
		evidencetools.StatusError, evidencetools.StatusTimeout, evidencetools.StatusUnsupported,
	}
	i := 0
	call := func(_ context.Context, tool string, _ json.RawMessage) (*evidencetools.Observation, error) {
		st := statuses[i]
		i++
		return &evidencetools.Observation{
			ID: "OBS-D", Tool: tool, Fact: "check did not produce a result",
			Scope: "check not performed", Completeness: evidencetools.CompletenessUnknown,
			ToolStatus: st, Error: "degraded: " + string(st),
		}, nil
	}
	trace, err := RunVerificationPlan(context.Background(), call, verificationPlanFixture(3, "search_source"), maxVerificationChecks)
	if err != nil {
		t.Fatal(err)
	}
	if trace.Complete || len(trace.Limitations) != 3 {
		t.Fatalf("complete=%v limitations=%v", trace.Complete, trace.Limitations)
	}
	for j, o := range trace.Observations {
		if o.ToolStatus != statuses[j] || o.Error == "" {
			t.Fatalf("observation %d lost its degraded status: %+v", j, o)
		}
		if !strings.Contains(trace.Limitations[j], string(statuses[j])) {
			t.Fatalf("limitation %d does not name status: %s", j, trace.Limitations[j])
		}
	}
}

// TestVerificationPlanRunToolError: a call that produces no observation
// becomes a synthesized ERROR record — never a silent skip — and later
// checks still execute (no retry, no abort).
func TestVerificationPlanRunToolError(t *testing.T) {
	i := 0
	call := func(_ context.Context, tool string, _ json.RawMessage) (*evidencetools.Observation, error) {
		i++
		if i == 1 {
			return nil, errors.New("tool call rejected: unknown tool \"shell\"")
		}
		return completeObs(tool), nil
	}
	trace, err := RunVerificationPlan(context.Background(), call, verificationPlanFixture(2, "search_source"), maxVerificationChecks)
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.Observations) != 2 {
		t.Fatalf("obs=%d, want 2 (failed call + completed call)", len(trace.Observations))
	}
	first := trace.Observations[0]
	if first.ToolStatus != evidencetools.StatusError || first.Completeness != evidencetools.CompletenessUnknown ||
		!strings.Contains(first.Error, "unknown tool") {
		t.Fatalf("synthesized ERROR observation: %+v", first)
	}
	if trace.Observations[1].ToolStatus != evidencetools.StatusOK {
		t.Fatalf("execution stopped after a tool error: %+v", trace.Observations[1])
	}
	if trace.Complete || len(trace.Limitations) == 0 || !strings.Contains(trace.Limitations[0], "check-a") {
		t.Fatalf("complete=%v limitations=%v", trace.Complete, trace.Limitations)
	}
}

// TestVerificationPlanRunCapExhaustion: the cap bounds dispatch; skipped
// checks are named and never retried. The slice hard cap of 8 applies
// even when the caller permits more.
func TestVerificationPlanRunCapExhaustion(t *testing.T) {
	calls := 0
	call := func(_ context.Context, tool string, _ json.RawMessage) (*evidencetools.Observation, error) {
		calls++
		return completeObs(tool), nil
	}
	trace, err := RunVerificationPlan(context.Background(), call, verificationPlanFixture(4, "search_source"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(trace.Observations) != 2 || len(trace.Requests) != 4 {
		t.Fatalf("calls=%d obs=%d reqs=%d", calls, len(trace.Observations), len(trace.Requests))
	}
	if trace.Complete {
		t.Fatal("capped plan must not be complete")
	}
	joined := strings.Join(trace.Limitations, "\n")
	for _, skipped := range []string{"check-c", "check-d"} {
		if !strings.Contains(joined, skipped) {
			t.Fatalf("skipped check %s not named in limitations: %s", skipped, joined)
		}
	}

	calls = 0
	trace, err = RunVerificationPlan(context.Background(), call, verificationPlanFixture(12, "search_source"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if calls != maxVerificationChecks || len(trace.Observations) != maxVerificationChecks {
		t.Fatalf("hard cap not enforced: calls=%d obs=%d", calls, len(trace.Observations))
	}
	if trace.Complete {
		t.Fatal("plan beyond the slice cap must not be complete")
	}
}

// TestVerificationPlanRunContextCancel: a dead context stops dispatch;
// remaining checks are recorded as skipped, never silently dropped.
func TestVerificationPlanRunContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	call := func(_ context.Context, tool string, _ json.RawMessage) (*evidencetools.Observation, error) {
		cancel()
		return completeObs(tool), nil
	}
	trace, err := RunVerificationPlan(ctx, call, verificationPlanFixture(3, "search_source"), maxVerificationChecks)
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.Observations) != 1 || trace.Complete {
		t.Fatalf("obs=%d complete=%v", len(trace.Observations), trace.Complete)
	}
	joined := strings.Join(trace.Limitations, "\n")
	if !strings.Contains(joined, "check-b") || !strings.Contains(joined, "check-c") {
		t.Fatalf("canceled checks not named: %s", joined)
	}
}

// TestVerificationPlanRunInvalidArgs: contract errors — no call
// function and a negative cap fail closed before any dispatch.
func TestVerificationPlanRunInvalidArgs(t *testing.T) {
	if _, err := RunVerificationPlan(context.Background(), nil, verificationPlanFixture(1, "x"), 1); err == nil {
		t.Fatal("nil call function must fail")
	}
	if _, err := RunVerificationPlan(context.Background(), func(context.Context, string, json.RawMessage) (*evidencetools.Observation, error) {
		return nil, nil
	}, verificationPlanFixture(1, "x"), -1); err == nil {
		t.Fatal("negative cap must fail")
	}
	// A plan with no checks produces an empty, complete trace.
	trace, err := RunVerificationPlan(context.Background(), func(context.Context, string, json.RawMessage) (*evidencetools.Observation, error) {
		t.Fatal("no checks must not dispatch")
		return nil, nil
	}, verificationPlanFixture(0, "x"), maxVerificationChecks)
	if err != nil || !trace.Complete || len(trace.Observations) != 0 {
		t.Fatalf("empty plan: trace=%+v err=%v", trace, err)
	}
}

// TestVerificationPlanSessionReuse exercises the factored session
// lifetime over the committed fixture: the same strict session that
// served the deterministic lane answers bounded verification calls,
// its audit trail records them, and Close releases it exactly once.
func TestVerificationPlanSessionReuse(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	advisory := `{
	  "id": "GO-TEST-0001",
	  "aliases": ["CVE-TEST-1"],
	  "summary": "test advisory for snapdep Parse",
	  "modified": "2026-01-01T00:00:00Z",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "example.com/snapdep"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
	    "ecosystem_specific": {"imports": [{"path": "example.com/snapdep/vuln", "symbols": ["Parse"]}]}
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.invalid/adv"}]
	}`
	advPath := filepath.Join(dir, "GO-TEST-0001.json")
	if err := os.WriteFile(advPath, []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	lane, es, err := RunDeterministicSession(ctx, LaneOptions{
		CVE: "GO-TEST-0001", SnapshotPath: root, AdvisoryFile: advPath,
		OutputDir: filepath.Join(dir, "out"), ExternalCommitSHA: "fixture-sha-1",
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("lane: %v", err)
	}
	if es == nil || es.Session() == nil {
		t.Fatal("session handle not returned")
	}
	if lane.ContentHash == "" {
		t.Fatal("no content hash")
	}
	// The lane drained its own records; the buffer starts empty for the
	// verification phase.
	if pending := es.DrainAudit(); len(pending) != 0 {
		t.Fatalf("lane left %d undrained audit records", len(pending))
	}

	plan := VerificationPlan{Falsifier: FalsifierProposal{
		Kind: domain.FalsifierPackageAbsent, ConditionID: "cond-1",
		Module: "example.com/snapdep", Package: "example.com/snapdep/vuln",
		Statement: "the vulnerable package is absent from the product", Scope: "product packages"},
		Checks: []VerificationRequest{
			{ID: "v1", Tool: "get_product_snapshot", Arguments: json.RawMessage(`{}`),
				Purpose: "pin snapshot identity", ConditionID: "cond-1"},
			{ID: "v2", Tool: "read_source", Arguments: json.RawMessage(`{"file":"main.go"}`),
				Purpose: "read confined source", ConditionID: "cond-1"},
		}}
	// Plan validation binds paths against the session's real roots.
	if err := ValidateVerificationPlan(plan, es.Session().SnapshotRoot, es.AdvisoryRoots()); err != nil {
		t.Fatalf("plan rejected inside session roots: %v", err)
	}
	trace, err := RunVerificationPlan(ctx, es.Call, plan, maxVerificationChecks)
	if err != nil {
		t.Fatalf("verification: %v", err)
	}
	if len(trace.Observations) != 2 {
		t.Fatalf("obs=%d", len(trace.Observations))
	}
	for i, o := range trace.Observations {
		if o.ID == "" || o.Tool != plan.Checks[i].Tool || o.ToolStatus == "" ||
			o.ScopeDetails == nil || o.ScopeDetails.SnapshotHash != lane.ContentHash ||
			o.ScopeDetails.Profile == "" {
			t.Fatalf("observation %d missing session scope details: %+v", i, o)
		}
	}
	// Every verification call produced a session audit record carrying
	// the request's exact arguments.
	recs := es.DrainAudit()
	if len(recs) != len(trace.Observations) {
		t.Fatalf("audit records=%d, want %d", len(recs), len(trace.Observations))
	}
	for i, r := range recs {
		var got map[string]any
		if json.Unmarshal(r.Args, &got) != nil {
			t.Fatalf("audit args undecodable: %s", r.Args)
		}
		var want map[string]any
		if json.Unmarshal(plan.Checks[i].Arguments, &want) != nil {
			t.Fatal("plan args fixture undecodable")
		}
		if len(got) != len(want) {
			t.Fatalf("audit args %s do not match request %s", r.Args, plan.Checks[i].Arguments)
		}
	}

	// The execution boundary still refuses paths outside the session
	// roots even when a plan was never validated.
	outside := filepath.Join(dir, "ground_truth.json")
	if err := os.WriteFile(outside, []byte(`{"label":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	o2, err := es.Call(ctx, "read_source", json.RawMessage(`{"file":"`+outside+`"}`))
	if err != nil {
		t.Fatalf("traversal must return an ERROR observation, not a transport failure: %v", err)
	}
	if o2.ToolStatus != evidencetools.StatusError || o2.Completeness != evidencetools.CompletenessUnknown {
		t.Fatalf("out-of-roots read: %+v", o2)
	}
	o2, err = es.Call(ctx, "definitely_not_a_tool", json.RawMessage(`{}`))
	if err == nil || o2 != nil {
		t.Fatalf("unknown tool must produce no observation: obs=%+v err=%v", o2, err)
	}

	if err := es.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// ---- Task 1 (B47): --modcache / --govulndb reach the strict session ----

func envHas(env []string, key, want string) bool {
	for _, kv := range env {
		if kv == key+"="+want {
			return true
		}
	}
	return false
}

func hasRoot(roots []string, want string) bool {
	for _, r := range roots {
		if r == want {
			return true
		}
	}
	return false
}

func canon(t *testing.T, p string) string {
	t.Helper()
	c, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("canonicalize %s: %v", p, err)
	}
	return c
}

// openResearchSession opens the strict evidence session over the
// committed fixture with the lane options under test.
func openResearchSession(t *testing.T, o LaneOptions, advPath string) *EvidenceSession {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "evidencesnap"))
	if err != nil {
		t.Fatal(err)
	}
	if canon, cerr := filepath.EvalSymlinks(root); cerr == nil {
		root = canon
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	es, err := openEvidenceSession(ctx, o, root, domain.ProductSnapshot{},
		toolchain.Toolchain{}, &AdvisoryRecord{Input: AdvisoryInput{SourcePath: advPath}}, nil)
	if err != nil {
		t.Fatalf("openEvidenceSession: %v", err)
	}
	t.Cleanup(func() { _ = es.Close() })
	return es
}

// B47: declared --modcache/--govulndb reach the strict session — the
// env pins name the canonical roots, the roots join the confined read
// set, and the recorded provenance is exactly what the tools use. With
// the roots omitted nothing ambient leaks in and govulncheck stays
// UNSUPPORTED.
func TestEvidenceSessionDeclaredRoots(t *testing.T) {
	dir := t.TempDir()
	advPath := filepath.Join(dir, "GO-TEST-0001.json")
	if err := os.WriteFile(advPath, []byte(`{"id":"GO-TEST-0001","affected":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	mc := filepath.Join(dir, "modcache")
	db := filepath.Join(dir, "govulndb")
	for _, d := range []string{mc, db} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(mc, "dep.go"), []byte("package dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ambient := filepath.Join(dir, "ambient-cache")
	if err := os.MkdirAll(ambient, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ambient, "dep.go"), []byte("package dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", ambient)

	es := openResearchSession(t, LaneOptions{
		CVE: "GO-TEST-0001", ModCache: mc, GovulnDB: db, Timeout: 30 * time.Second,
	}, advPath)
	sess := es.Session()
	mcCanon, dbCanon, advCanon := canon(t, mc), canon(t, db), canon(t, dir)
	if sess.ModCacheRoot != mcCanon {
		t.Fatalf("session ModCacheRoot=%q want canonical %q", sess.ModCacheRoot, mcCanon)
	}
	if sess.GovulnDBRoot != dbCanon {
		t.Fatalf("session GovulnDBRoot=%q want canonical %q", sess.GovulnDBRoot, dbCanon)
	}
	if !envHas(sess.ToolEnv, "GOMODCACHE", mcCanon) {
		t.Fatalf("GOMODCACHE pin missing from toolchain env: %v", sess.ToolEnv)
	}
	if !envHas(sess.ToolEnv, "GOVULNDB", dbCanon) {
		t.Fatalf("GOVULNDB pin missing from toolchain env: %v", sess.ToolEnv)
	}
	for _, want := range []string{mcCanon, dbCanon, advCanon, sess.SnapshotRoot} {
		if !hasRoot(sess.ReadRoots, want) {
			t.Fatalf("read roots %v missing %s", sess.ReadRoots, want)
		}
	}
	// The declared roots never widen confinement: the ambient cache and
	// arbitrary outside paths stay unreadable inside this session.
	if hasRoot(sess.ReadRoots, canon(t, ambient)) {
		t.Fatalf("ambient cache leaked into read roots: %v", sess.ReadRoots)
	}
	o, err := es.Call(context.Background(), "read_source",
		json.RawMessage(`{"file":"`+filepath.Join(mc, "dep.go")+`"}`))
	if err != nil {
		t.Fatalf("declared-cache read: %v", err)
	}
	if o.ToolStatus != evidencetools.StatusOK {
		t.Fatalf("declared module cache must be readable in-session: %+v", o)
	}
	o, err = es.Call(context.Background(), "read_source",
		json.RawMessage(`{"file":"`+filepath.Join(ambient, "dep.go")+`"}`))
	if err != nil {
		t.Fatalf("ambient-cache read: %v", err)
	}
	if o.ToolStatus != evidencetools.StatusError {
		t.Fatalf("ambient cache must stay outside the read roots: %+v", o)
	}

	// Omitted roots: govulncheck is UNSUPPORTED (never an ambient scan),
	// and the env pin blocks every ambient module cache.
	es2 := openResearchSession(t, LaneOptions{
		CVE: "GO-TEST-0001", Timeout: 30 * time.Second,
	}, advPath)
	sess2 := es2.Session()
	if sess2.ModCacheRoot != "" || sess2.GovulnDBRoot != "" {
		t.Fatalf("undeclared roots must stay empty, got modcache=%q govulndb=%q",
			sess2.ModCacheRoot, sess2.GovulnDBRoot)
	}
	v, ok := envValueOf(sess2.ToolEnv, "GOMODCACHE")
	if !ok || v == ambient {
		t.Fatalf("omitted modcache must pin GOMODCACHE away from ambient, got %q ok=%v", v, ok)
	}
	o, err = es2.Call(context.Background(), "run_govulncheck", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("run_govulncheck: %v", err)
	}
	if o.ToolStatus != evidencetools.StatusUnsupported {
		t.Fatalf("run_govulncheck without declared govulndb must be UNSUPPORTED, got %s", o.ToolStatus)
	}

	// A declared-but-missing govulndb root is an absent capability, not
	// a silent ambient fallback: UNSUPPORTED, never a scan.
	missing := filepath.Join(dir, "no-such-db")
	es3 := openResearchSession(t, LaneOptions{
		CVE: "GO-TEST-0001", ModCache: mc, GovulnDB: missing, Timeout: 30 * time.Second,
	}, advPath)
	o, err = es3.Call(context.Background(), "run_govulncheck", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("run_govulncheck(missing db): %v", err)
	}
	if o.ToolStatus != evidencetools.StatusUnsupported ||
		!strings.Contains(o.Error, "missing") && !strings.Contains(o.Error, "unreadable") {
		t.Fatalf("missing govulndb must be UNSUPPORTED, got %+v", o)
	}
}

func envValueOf(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

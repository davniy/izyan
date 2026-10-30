package states_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/exploit"
	"github.com/davniy/izyan/internal/fix"
	"github.com/davniy/izyan/internal/goanalysis"
	"github.com/davniy/izyan/internal/llm"
	"github.com/davniy/izyan/internal/persistence/filesystem"
	"github.com/davniy/izyan/internal/repository"
	"github.com/davniy/izyan/internal/review"
	"github.com/davniy/izyan/internal/rootcause"
	"github.com/davniy/izyan/internal/states"
	"github.com/davniy/izyan/internal/toolaudit"
	"github.com/davniy/izyan/internal/vulnerability"
	"github.com/davniy/izyan/internal/workflow"
)

const xnetOSV = `{
  "id": "GO-2024-2687",
  "aliases": ["CVE-2024-45338"],
  "summary": "Non-linear parsing in golang.org/x/net/html",
  "affected": [{
    "package": {"name": "golang.org/x/net", "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.33.0"}]}],
    "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/html", "symbols": ["Parse"]}]}
  }]
}`

// hasAnalysisGap reports whether the case carries the typed cause. Outcome
// classification is structural; tests assert on codes, never on text.
func hasAnalysisGap(c *domain.AnalysisCase, code domain.GapCode) bool {
	for _, g := range c.AnalysisGaps {
		if g.Code == code {
			return true
		}
	}
	return false
}

// requireAssessmentFailed asserts the new terminal policy: no public verdict
// and the named typed cause. An unfinished analysis is never INCONCLUSIVE.
func requireAssessmentFailed(t *testing.T, c *domain.AnalysisCase, code domain.GapCode) {
	t.Helper()
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v, want none for a failed assessment", c.Verdict)
	}
	if !hasAnalysisGap(c, code) {
		t.Fatalf("missing analysis gap %s: %+v", code, c.AnalysisGaps)
	}
}

func initRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	return initGit(t, dir)
}

// initRepoFrom copies a testdata fixture into a temp dir and git-inits it,
// so the case is bound to a concrete commit as the spec requires. The
// module fixtures every product may address relatively (dep, postreachdep)
// are always present; additional fixtures are copied once each, so a caller
// can name a shared library module and still get one checkout.
func initRepoFrom(t *testing.T, fixture string, additional ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	copied := map[string]bool{}
	for _, sub := range append([]string{fixture, "dep", "postreachdep"}, additional...) {
		if copied[sub] {
			continue
		}
		copied[sub] = true
		fsys := os.DirFS(filepath.Join(src, sub))
		dst := filepath.Join(dir, sub)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(dst, fsys); err != nil {
			t.Fatal(err)
		}
	}
	return initGit(t, filepath.Join(dir, fixture))
}

func initGit(t *testing.T, dir string) string {
	t.Helper()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		write("go.mod", "module example.com/product\n\ngo 1.23\n")
		write("main.go", "package main\n\nfunc main() {}\n")
	}
	for _, args := range [][]string{
		{"git", "init", "-q"},
		{"git", "add", "."},
		{"git", "-c", "user.email=test@test", "-c", "user.name=test", "commit", "-qm", "init"},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	return dir
}

type engineDeps struct {
	RepoPath    string
	VulnSrc     vulnerability.Source
	VulnID      string
	Resolver    affected.Resolver
	ManualRC    []domain.RootCause
	Model       string
	CaseDir     string
	Govulncheck goanalysis.Runner
	UseSource   bool // wire the go/packages source index + verifier
	AllowExec   bool // permit the gap loop's build/test evidence actions
	// SnapshotOptions declares the analyzed build. The zero value stays a
	// host-default analysis context, which cannot ground a build-dependent
	// negative; fixtures that assert one must declare their build here.
	SnapshotOptions repository.SnapshotOptions
	RCResolver      states.RootCauseResolver // overrides default rootcause.Resolver
	// Assumptions is the declared-assumptions/1 channel input for the
	// case — policy inputs, never evidence.
	Assumptions *domain.DeclaredAssumptionsInput
}

func runEngine(t *testing.T, d engineDeps) *domain.AnalysisCase {
	t.Helper()
	store := filesystem.New(d.CaseDir)
	c := &domain.AnalysisCase{
		ID: domain.CaseID("test-" + d.VulnID),
		Workflow: domain.WorkflowStatus{
			State:     domain.StateCreated,
			StartedAt: time.Now().UTC(),
			Limits:    domain.AnalysisLimits{MaxIterations: 64},
		},
		DeclaredAssumptions: d.Assumptions,
	}
	c.EvidenceGraph.Version = "1"
	if err := store.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	var srcIndex *goanalysis.Index
	if d.UseSource {
		srcIndex = &goanalysis.Index{Dir: d.RepoPath}
	}
	rc := states.ResolveRootCause{Manual: d.ManualRC}
	if d.UseSource {
		rc.Resolver = &rootcause.Resolver{Fix: fix.Resolver{}}
		rc.Verifier = &rootcause.Verifier{Source: srcIndex}
	}
	if d.RCResolver != nil {
		rc.Resolver = d.RCResolver
	}
	e := workflow.New(store,
		states.Created{},
		states.SnapshotProduct{Repo: repository.Service{}, Path: d.RepoPath, Options: d.SnapshotOptions, Source: srcIndex},
		states.ResolveVulnerability{Source: d.VulnSrc, ID: d.VulnID},
		states.CheckAffected{Resolver: d.Resolver},
		rc,
		states.BuildExploitModel{ModelPath: d.Model, Builder: exploitBuilder(srcIndex)},
		states.CollectEvidence{Govulncheck: d.Govulncheck, Source: srcIndex},
		states.EvaluateConditions{Evaluators: []evaluator.ConditionEvaluator{
			evaluator.SymbolReachable{},
			evaluator.ArgumentOrigin{},
			evaluator.Validation{},
			evaluator.MissingCall{},
			evaluator.Exposure{},
			evaluator.ConfigFlag{},
			evaluator.Presence{},
			evaluator.Platform{},
		}},
		states.GapAnalysis{Source: srcIndex, AllowExec: d.AllowExec, Evaluators: []evaluator.ConditionEvaluator{
			evaluator.SymbolReachable{},
			evaluator.ArgumentOrigin{},
			evaluator.Validation{},
			evaluator.MissingCall{},
			evaluator.Exposure{},
			evaluator.ConfigFlag{},
			evaluator.Presence{},
			evaluator.Platform{},
		}},
		states.NegativeCheck{Verifier: &goanalysis.Verifier{Source: srcIndex}},
		states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}},
		states.RepairAnalysis{},
		states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
		states.BuildReport{Dir: filepath.Join(d.CaseDir, string(c.ID))},
	)
	ctx := toolaudit.WithRecorder(context.Background(),
		&toolaudit.Recorder{Sink: c.EvidenceGraph.AddToolExecution})
	if err := e.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	return c
}

// Every real subprocess the pipeline spawns must land in the case's
// tool_executions audit trail (spec §22): at minimum the snapshot's
// git rev-parse and `go version` probes.
func TestE2EToolExecutionsRecorded(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	if err := os.WriteFile(vulnPath, []byte(xnetOSV), 0o644); err != nil {
		t.Fatal(err)
	}
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-2024-3333",
		Resolver: stubResolver{},
		CaseDir:  filepath.Join(dir, "cases"),
	})
	tools := map[string]bool{}
	for _, tx := range c.EvidenceGraph.ToolExecutions {
		tools[tx.Tool] = true
		if tx.ID == "" {
			t.Fatalf("execution without id: %+v", tx)
		}
		if tx.Tool == "git" && (tx.ExitCode != 0 || tx.StdoutSHA256 == "") {
			t.Fatalf("bad git record: %+v", tx)
		}
	}
	if !tools["git"] || !tools["go"] {
		t.Fatalf("want git+go executions recorded, got %v", c.EvidenceGraph.ToolExecutions)
	}
}

// Golden case: module absent from the dependency graph -> NOT_AFFECTED,
// reached entirely by deterministic tooling.
func TestE2ENotAffected(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	if err := os.WriteFile(vulnPath, []byte(xnetOSV), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-2024-2687",
		Resolver: affected.GoResolver{},
		CaseDir:  caseDir,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNotAffected {
		t.Fatalf("verdict=%+v", c.Verdict)
	}
	if c.Affected == nil || c.Affected.ModulePresent != domain.ClaimFalse {
		t.Fatalf("affected=%+v", c.Affected)
	}
	if len(c.EvidenceGraph.Evidence) == 0 || c.EvidenceGraph.Hash == "" {
		t.Fatal("evidence graph must contain the go list artifact and a hash")
	}
	for _, f := range []string{"report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(caseDir, string(c.ID), f)); err != nil {
			t.Fatalf("missing report artifact %s: %v", f, err)
		}
	}
}

// Affected dependency without any root cause input is unfinished analysis:
// the case fails with a typed cause and still writes its diagnostic report.
func TestE2EAffectedNoRootCause(t *testing.T) {
	repo := initRepo(t)
	caseDir := t.TempDir()

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/product"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		CaseDir:  caseDir,
	})
	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s, want FAILED", c.Workflow.State)
	}
	requireAssessmentFailed(t, c, domain.GapRootCauseUnresolved)
	for _, f := range []string{"report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(caseDir, string(c.ID), f)); err != nil {
			t.Fatalf("failure report missing %s: %v", f, err)
		}
	}
}

// Manual root cause + manual exploit model still cannot reach a verdict
// without evidence collectors: every condition stays UNKNOWN and the
// unfinished analysis fails.
func TestE2EManualModelFails(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	model := domain.ExploitModel{
		Impact: "test",
		MandatoryConditions: []domain.Condition{
			{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true, Description: "symbol reachable"},
		},
	}
	mb, _ := json.Marshal(model)
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, mb, 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/product"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/product", Symbol: "main", Role: domain.RootCauseSink}},
		Model:    mp,
		CaseDir:  caseDir,
	})

	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
	}
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v, want none for unresolved mandatory conditions", c.Verdict)
	}
	if len(c.Claims) != 1 || c.Claims[0].Result != domain.ClaimUnknown {
		t.Fatalf("claims=%+v, want one UNKNOWN", c.Claims)
	}
	if !hasAnalysisGap(c, domain.GapReachabilityProofIncomplete) {
		t.Fatalf("missing reachability cause: %+v", c.AnalysisGaps)
	}
}

// SYMBOL_REACHABLE happy path: govulncheck reports a call path to the
// root-cause symbol -> claim TRUE. Remaining conditions stay UNKNOWN so the
// verdict is INCONCLUSIVE, not EXPLOITABLE.
func TestE2ESymbolReachableTrue(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,"description":"Parse reachable"},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,"description":"attacker controls input"}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/product","package":"example.com/product","function":"main","position":{"filename":"/repo/main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"/dep/vuln/vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink}},
		Model:    mp,
		CaseDir:  caseDir,
		Govulncheck: fakeGovulncheck{
			out: []byte(gv),
		},
	})

	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
	}
	if len(c.EvidenceGraph.CallPaths) != 1 {
		t.Fatalf("call paths=%+v", c.EvidenceGraph.CallPaths)
	}
	claim := findClaimT(t, c.Claims, "C-REACH")
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("C-REACH=%s want TRUE (claim=%+v)", claim.Result, claim)
	}
	if len(claim.EvidenceIDs) == 0 {
		t.Fatal("TRUE claim must cite evidence")
	}
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v want none (C-INPUT unresolved)", c.Verdict)
	}
	if !hasAnalysisGap(c, domain.GapInputTraceIncomplete) {
		t.Fatalf("missing input-trace cause: %+v", c.AnalysisGaps)
	}
}

// govulncheck ran clean and found no call path, but absence of call sites is
// not evidence with no usage scan: C-REACH stays UNKNOWN and the analysis
// fails — never NO_EXPLOIT_PATH_FOUND and never a bare INCONCLUSIVE.
func TestE2ENoPathFails(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,"description":"Parse reachable"}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:    mp,
		CaseDir:  caseDir,
		Govulncheck: fakeGovulncheck{
			out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`),
		},
	})

	// No module-usage scan is configured in this engine, so the absence of
	// call sites is not evidence: C-REACH stays UNKNOWN, never FALSE.
	claim := findClaimT(t, c.Claims, "C-REACH")
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("C-REACH=%s want UNKNOWN (no usage scan ran)", claim.Result)
	}
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v want none: the unresolved condition fails the analysis", c.Verdict)
	}
}

func findClaimT(t *testing.T, claims []domain.Claim, id domain.ConditionID) domain.Claim {
	t.Helper()
	for _, cl := range claims {
		if cl.ConditionID == id {
			return cl
		}
	}
	t.Fatalf("claim for %s not found: %+v", id, claims)
	return domain.Claim{}
}

type fakeGovulncheck struct {
	out []byte
	err error
	// pattern is the scan pattern the runner reports. Empty keeps the
	// whole-build "./..." default.
	pattern string
}

func (f fakeGovulncheck) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	pattern := f.pattern
	if pattern == "" {
		pattern = "./..."
	}
	return f.out, pattern, f.err
}

type stubResolver struct{}

func (stubResolver) Resolve(_ context.Context, vuln domain.Vulnerability, _ domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	return domain.AffectedResult{
		Scope:           vuln.Scope,
		ModulePresent:   domain.ClaimTrue,
		ResolvedVersion: "v1.0.0",
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}, nil, nil
}

// exactTestVuln is the advisory fixture of the end-to-end negative cases: an
// exact GO- identity over example.com/dep whose synthetic record is declared
// fully represented, so a verified negative may close the requested finding.
// Cases that only prove a positive keep the bare fixture — scope never gates a
// proven positive.
func exactTestVuln() *domain.Vulnerability {
	return &domain.Vulnerability{
		ID:     "GO-TEST-1",
		Module: "example.com/dep",
		Scope:  exactScopeFor("GO-TEST-1", "example.com/dep"),
	}
}

// Slice 3 golden: the vulnerable symbol IS reachable (govulncheck trace) but
// the only call site passes a constant argument. ATTACKER_CONTROL goes FALSE,
// negative verification confirms every call site is non-external, and the
// verdict is NO_EXPLOIT_PATH_FOUND — the first verified-safe path.
func TestE2EConstantInputVerifiedFalse(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": exactTestVuln(),
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		// The analyzed build is this fixture's product build, not the
		// analyzer host: the constant-NEPF expectation is build-dependent.
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	claim := findClaimT(t, c.Claims, "C-INPUT")
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("C-INPUT=%s want FALSE", claim.Result)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("neg verification=%+v want VERIFIED", claim.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
	if len(c.EvidenceGraph.DataFlows) == 0 {
		t.Fatal("expected provenance data flows in evidence graph")
	}
}

// External input at the sink argument -> ATTACKER_CONTROL TRUE -> with
// reachability also TRUE the deterministic verdict is EXPLOITABLE.
func TestE2EExternalInputTrue(t *testing.T) {
	repo := initRepoFrom(t, "extprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/extprod","package":"example.com/extprod","function":"main","position":{"filename":"main.go","line":10}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})

	claim := findClaimT(t, c.Claims, "C-INPUT")
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("C-INPUT=%s want TRUE", claim.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// Function-value escape: govulncheck reports no call path (FALSE candidate)
// but ScanDynamic finds `f := vuln.Parse` — the falsification pass demotes
// FALSE to UNKNOWN and the verdict stays INCONCLUSIVE, honoring the invariant
// that absence of evidence is not absence of exploitability.
func TestE2EFuncValueDemotesFalse(t *testing.T) {
	repo := initRepoFrom(t, "funcvalprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:          "GO-TEST-1",
		Resolver:        stubResolver{},
		ManualRC:        []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:           mp,
		CaseDir:         caseDir,
		Govulncheck:     fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`)},
		UseSource:       true,
		SnapshotOptions: declaredSnapshotOptions(),
	})

	claim := findClaimT(t, c.Claims, "C-REACH")
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("C-REACH=%s want UNKNOWN after contradiction", claim.Result)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("neg verification=%+v want CONTRADICTED", claim.NegativeVerification)
	}
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v want none: the contradicted negative leaves the condition unresolved", c.Verdict)
	}
	if !hasAnalysisGap(c, domain.GapReachabilityProofIncomplete) {
		t.Fatalf("missing reachability cause: %+v", c.AnalysisGaps)
	}
}

// Slice 4 golden: no --root-cause flag — the pipeline derives the root cause
// from advisory affected symbols (AUTHORITATIVE evidence) and verifies the
// symbol exists in the dependency source. Same verdict path as the manual
// constprod case.
func TestE2EAutoRootCause(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	osv := `{"id":"GO-TEST-AUTO","summary":"auto rc",
 "affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},
  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}],
  "ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse"]}]}}],
 "references":[{"type":"ADVISORY","url":"https://example.com/adv"}]}`
	if err := os.WriteFile(vulnPath, []byte(osv), 0o644); err != nil {
		t.Fatal(err)
	}
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-AUTO","fixed_version":"v1.0.1","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-TEST-AUTO",
		Resolver: stubResolver{},
		// no ManualRC — resolved automatically
		Model:           mp,
		CaseDir:         caseDir,
		Govulncheck:     fakeGovulncheck{out: []byte(gv)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if c.RootCause == nil || c.RootCause.Status != domain.RootCauseResolved {
		t.Fatalf("rootcause=%+v", c.RootCause)
	}
	if len(c.RootCause.RootCauses) != 1 || c.RootCause.RootCauses[0].Symbol != "Parse" {
		t.Fatalf("root causes=%+v", c.RootCause.RootCauses)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

func exploitBuilder(ix *goanalysis.Index) *exploit.Builder {
	if ix == nil {
		return nil
	}
	return &exploit.Builder{Source: ix}
}

// Slice 5 golden: fully automatic — no --root-cause, no --exploit-model.
// The builder derives mandatory conditions from the resolved root cause;
// on constprod the same verified-FALSE path yields NO_EXPLOIT_PATH_FOUND.
func TestE2EAutoExploitModel(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	osv := `{"id":"GO-TEST-AUTO","summary":"auto model",
 "affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},
  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}],
  "ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse"]}]}}],
 "references":[{"type":"ADVISORY","url":"https://example.com/adv"}]}`
	if err := os.WriteFile(vulnPath, []byte(osv), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-AUTO","fixed_version":"v1.0.1","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-TEST-AUTO",
		Resolver: stubResolver{},
		CaseDir:  caseDir,
		// no ManualRC, no Model — both derived automatically
		Govulncheck:     fakeGovulncheck{out: []byte(gv)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if c.Exploit == nil || len(c.Exploit.MandatoryConditions) == 0 {
		t.Fatal("expected auto-built exploit model")
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

// B30 regression — the GO-2026-6443 shape: the advisory declares a sink
// in a feature-gated package absent from the product's dependency source
// (like grpc's internal/xds/server in a build without xDS). Verification
// drops it, but the exploit model must not claim completeness: the
// remaining sinks satisfy their conditions yet the verdict is
// INCONCLUSIVE, not EXPLOITABLE.
func TestE2EUnresolvedSinkBlocksExploitable(t *testing.T) {
	repo := initRepoFrom(t, "extprod")
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	osv := `{"id":"GO-TEST-GATE","summary":"mode-gated defect",
 "affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},
  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}],
  "ecosystem_specific":{"imports":[
   {"path":"example.com/dep/vuln","symbols":["Parse"]},
   {"path":"example.com/dep/mode","symbols":["RouteAndProcess"]}]}}],
 "references":[{"type":"ADVISORY","url":"https://example.com/adv"}]}`
	if err := os.WriteFile(vulnPath, []byte(osv), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-GATE","fixed_version":"v1.0.1","trace":[
 {"module":"example.com/extprod","package":"example.com/extprod","function":"main","position":{"filename":"main.go","line":10}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-TEST-GATE",
		Resolver: stubResolver{},
		CaseDir:  caseDir,
		// no ManualRC, no Model — both derived automatically
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})

	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
	}
	if c.Exploit == nil || len(c.Exploit.UnresolvedSubjects) != 1 ||
		c.Exploit.UnresolvedSubjects[0].Symbol != "RouteAndProcess" {
		t.Fatalf("unresolved=%+v — dropped in-scope sink must surface on the model",
			c.Exploit.UnresolvedSubjects)
	}
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v want none — incomplete model must not claim EXPLOITABLE", c.Verdict)
	}
	if !hasAnalysisGap(c, domain.GapReachabilityProofIncomplete) {
		t.Fatalf("missing reachability cause: %+v", c.AnalysisGaps)
	}
}

func TestReviewDemotesUnsupportedTrue(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{ID: "C-1", Kind: domain.ConditionSymbolReachable}},
		},
		RootCause: &domain.RootCauseModel{Status: domain.RootCauseResolved},
		Claims: []domain.Claim{{
			ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue,
		}},
	}
	h := states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}}
	tr, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateRepairAnalysis {
		t.Fatalf("next = %s, want REPAIR_ANALYSIS", tr.Next)
	}
	if len(c.Reviews) != 1 || c.Reviews[0].Result != domain.ReviewRevise {
		t.Fatalf("reviews: %+v", c.Reviews)
	}
	// The claim is still TRUE until the repair state runs.
	if c.Claims[0].Result != domain.ClaimTrue {
		t.Fatalf("claim demoted inside REVIEW, before repair: %s", c.Claims[0].Result)
	}
	tr, err = states.RepairAnalysis{}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next = %s, want re-REVIEW after repair", tr.Next)
	}
	if c.Claims[0].Result != domain.ClaimUnknown {
		t.Fatalf("claim not demoted: %s", c.Claims[0].Result)
	}
	if len(c.Claims[0].Limitations) == 0 {
		t.Fatal("demotion must record a limitation")
	}
}

func TestReviewBudgetExhausted(t *testing.T) {
	c := &domain.AnalysisCase{
		Reviews: []domain.Review{{Result: domain.ReviewRevise}, {Result: domain.ReviewRevise}},
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{MaxReviewIterations: 2},
		},
	}
	h := states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}}
	tr, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next = %s", tr.Next)
	}
	if !hasAnalysisGap(c, domain.GapReviewUnresolved) {
		t.Fatalf("review budget exhaustion lacks its typed cause: %+v", c.AnalysisGaps)
	}
}

// Tool failure is never negative evidence: a govulncheck error must not
// fabricate a FALSE on C-REACH. The two admission gates are independent, so
// this test crosses them: the same failed run keeps an independent direct-call
// positive, and a product with no usage at all stays UNKNOWN — under a
// declared product build just as under the analyzer host, because a missing
// measurement is not repaired by a target.
func TestE2EGovulncheckFailureStaysInconclusive(t *testing.T) {
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"@PACKAGE@","symbol":"@SYMBOL@"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"@PACKAGE@","symbol":"@SYMBOL@"},"arg_index":0}
	]}`

	// run drives one case against the named fixture with a failed
	// govulncheck measurement; the terminal state is asserted per subtest.
	run := func(t *testing.T, fixture, module string, subject domain.SymbolRef, options repository.SnapshotOptions, extra ...string) *domain.AnalysisCase {
		t.Helper()
		mp := filepath.Join(t.TempDir(), "model.json")
		doc := strings.ReplaceAll(strings.ReplaceAll(model, "@PACKAGE@", subject.Package), "@SYMBOL@", subject.Symbol)
		if err := os.WriteFile(mp, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		c := runEngine(t, engineDeps{
			RepoPath: initRepoFrom(t, fixture, extra...),
			VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
				"GO-TEST-1": {ID: "GO-TEST-1", Module: module},
			}},
			VulnID:          "GO-TEST-1",
			Resolver:        stubResolver{},
			ManualRC:        []domain.RootCause{{Package: subject.Package, Symbol: subject.Symbol}},
			Model:           mp,
			CaseDir:         filepath.Join(t.TempDir(), "cases"),
			Govulncheck:     fakeGovulncheck{err: fmt.Errorf("govulncheck: binary missing")},
			SnapshotOptions: options,
			UseSource:       true,
		})
		rec := runOutcome(t, c).Govulncheck
		if rec.Outcome != domain.GovulncheckFailed || rec.Error == "" {
			t.Fatalf("run outcome=%s error=%q, want the injected failure", rec.Outcome, rec.Error)
		}
		assertNoSilenceFalsifier(t, c)
		return c
	}

	t.Run("independent direct-call positive survives the failure", func(t *testing.T) {
		// extprod passes os.Args into the sink: the only path to a
		// non-INCONCLUSIVE verdict would be a fabricated FALSE on C-REACH —
		// the bug this test guards against.
		c := run(t, "extprod", "example.com/dep",
			domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}, repository.SnapshotOptions{})
		reach := findClaimT(t, c.Claims, "C-REACH")
		if reach.Result != domain.ClaimTrue {
			t.Fatalf("C-REACH=%s want TRUE via module usage", reach.Result)
		}
		if reach.Falsifier != "" {
			t.Fatalf("C-REACH TRUE carries falsifier %q", reach.Falsifier)
		}
		// Module-usage evidence made C-REACH legitimately TRUE — with
		// C-INPUT also TRUE the verdict is EXPLOITABLE despite the failed
		// measurement, which stays a recorded diagnostic.
		if c.Workflow.State != domain.StateCompleted {
			t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
		}
		if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
		}
		if !hasAnalysisGap(c, domain.GapMeasurementNotCompleted) {
			t.Fatalf("failed measurement diagnostic was lost: %+v", c.AnalysisGaps)
		}
	})

	t.Run("zero usage stays UNKNOWN with no silence-derived falsifier", func(t *testing.T) {
		// initRepo's product does not import the advisory module at all: the
		// module-usage scan runs, finds nothing, and must not turn that
		// absence into no-module-usage while the run never measured.
		subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
		for _, tc := range []struct {
			name    string
			options repository.SnapshotOptions
		}{
			{"host default", repository.SnapshotOptions{}},
			{"operator-declared build", declaredSnapshotOptions()},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// unusedprod requires the module but never imports it: the
				// usage scan measures zero call sites.
				c := run(t, "unusedprod", "example.com/dep", subject, tc.options)
				reach := findClaimT(t, c.Claims, "C-REACH")
				if reach.Result != domain.ClaimUnknown {
					t.Fatalf("C-REACH=%s (%s), want UNKNOWN under a failed run", reach.Result, reach.Explanation)
				}
				if reach.Falsifier != "" {
					t.Fatalf("C-REACH UNKNOWN carries falsifier %q", reach.Falsifier)
				}
				input := findClaimT(t, c.Claims, "C-INPUT")
				if input.Result == domain.ClaimFalse {
					t.Fatalf("failed run produced FALSE on C-INPUT: %+v", input)
				}
				if c.Workflow.State != domain.StateFailed {
					t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
				}
				if c.Verdict != nil {
					t.Fatalf("verdict=%+v want none under a failed run", c.Verdict)
				}
				if !hasAnalysisGap(c, domain.GapMeasurementNotCompleted) {
					t.Fatalf("missing measurement cause: %+v", c.AnalysisGaps)
				}
			})
		}
	})

	t.Run("used module with an unused sink stays UNKNOWN", func(t *testing.T) {
		// unreachprod links the module and calls Benign, but never invokes
		// the declared sink: a declared build target cannot turn the absence
		// of a measurement into a negative.
		c := run(t, "unreachprod", "example.com/unreachdep",
			domain.SymbolRef{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
			declaredSnapshotOptions(), "unreachdep")
		reach := findClaimT(t, c.Claims, "C-REACH")
		if reach.Result != domain.ClaimUnknown {
			t.Fatalf("C-REACH=%s (%s), want UNKNOWN", reach.Result, reach.Explanation)
		}
		if reach.Falsifier != "" {
			t.Fatalf("C-REACH UNKNOWN carries falsifier %q", reach.Falsifier)
		}
		if c.Workflow.State != domain.StateFailed {
			t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
		}
		if c.Verdict != nil {
			t.Fatalf("verdict=%+v want none under a failed run", c.Verdict)
		}
		if !hasAnalysisGap(c, domain.GapMeasurementNotCompleted) {
			t.Fatalf("missing measurement cause: %+v", c.AnalysisGaps)
		}
	})
}

// Deployment-dependent provenance: a flag-fed sink argument is neither
// provably safe nor provably attacker-controlled — the claim must stay
// UNKNOWN and the case INCONCLUSIVE (spec §12: no silent default-config
// generalization).
func TestE2EConfigInputStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "configprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/configprod","package":"example.com/configprod","function":"main","position":{"filename":"main.go","line":17}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var input *domain.Claim
	for i := range c.Claims {
		if c.Claims[i].ConditionID == "C-INPUT" {
			input = &c.Claims[i]
		}
	}
	if input == nil || input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%+v want UNKNOWN", input)
	}
	requireAssessmentFailed(t, c, domain.GapInputTraceIncomplete)
}

// Database-populated input is neither attacker-controlled nor safe:
// DATABASE provenance -> deploy-dependent UNKNOWN -> INCONCLUSIVE.
func TestE2EDatabaseOriginStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "dbprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/dbprod","package":"example.com/dbprod","function":"main","position":{"filename":"main.go","line":19}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawDB bool
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.Origin == domain.OriginDatabase {
			sawDB = true
		}
	}
	if !sawDB {
		t.Fatalf("no DATABASE flow recorded; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%s want UNKNOWN (database is deploy-dependent)", input.Result)
	}
	requireAssessmentFailed(t, c, domain.GapInputTraceIncomplete)
}

// A configured internal-service endpoint produces INTERNAL_SERVICE
// provenance: not externally attacker-controlled, not constant —
// deploy-dependent UNKNOWN -> INCONCLUSIVE.
func TestE2EInternalServiceOriginStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "svcprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/svcprod","package":"example.com/svcprod","function":"main","position":{"filename":"main.go","line":21}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawSvc bool
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.Origin == domain.OriginInternalService {
			sawSvc = true
		}
	}
	if !sawSvc {
		t.Fatalf("no INTERNAL_SERVICE flow recorded; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%s want UNKNOWN (internal service is deploy-dependent)", input.Result)
	}
	requireAssessmentFailed(t, c, domain.GapInputTraceIncomplete)
}

// Three-hop parameter chain — deeper than the default provenance bound.
// The gap-analysis loop must record a CONFIRMED hypothesis and resolve
// the argument origin to EXTERNAL, flipping C-INPUT to TRUE.
func TestE2EGapAnalysisDeepTrace(t *testing.T) {
	repo := initRepoFrom(t, "deepprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/deepprod","package":"example.com/deepprod","function":"level3","position":{"filename":"main.go","line":24}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var confirmed bool
	for _, h := range c.Hypotheses {
		if h.Status == domain.HypothesisConfirmed {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatalf("no CONFIRMED hypothesis recorded; hypotheses=%+v", c.Hypotheses)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimTrue {
		t.Fatalf("C-INPUT=%s want TRUE (deep trace resolved external)", input.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// Advisory names a symbol that does not exist in the dependency source:
// all candidates fail verification -> AMBIGUOUS -> INCONCLUSIVE.
func TestE2EAmbiguousRootCause(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {
				ID:     "GO-TEST-1",
				Module: "example.com/dep",
				AffectedPackages: []domain.AffectedPackage{{
					Path:    "example.com/dep/vuln",
					Symbols: []string{"Nonexistent"},
				}},
				AffectedSymbols: []domain.SymbolRef{
					{Package: "example.com/dep/vuln", Symbol: "Nonexistent"},
				},
			},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`)},
		UseSource:   true,
	})
	if c.RootCause == nil || c.RootCause.Status != domain.RootCauseAmbiguous {
		t.Fatalf("root cause=%+v", c.RootCause)
	}
	// An ambiguous root cause no longer aborts before a verdict: the case
	// records the typed failure and still writes its reports/exports.
	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s, want FAILED with a diagnostic report", c.Workflow.State)
	}
	requireAssessmentFailed(t, c, domain.GapRootCauseUnresolved)
}

// A resolver whose verified-failed candidates get a second chance via
// the RootCauseProposer hook; proposals pass through the same verifier.
type retryResolver struct{ proposed bool }

func (r *retryResolver) Resolve(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	return &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "AddedOnlyByFix",
			Role: domain.RootCauseSink, Mechanism: "fix-commit candidate",
		}},
	}, nil, nil
}

func (r *retryResolver) Propose(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability) ([]domain.RootCause, []string, error) {
	r.proposed = true
	return []domain.RootCause{{
		Package: "example.com/dep/vuln", Symbol: "Parse",
		Role: domain.RootCauseSink, Mechanism: "retry proposal",
	}}, nil, nil
}

// Fix commits may name symbols that only exist post-fix; verification
// drops them -> the Proposer hook supplies a verified replacement.
func TestRootCauseRetryOnVerificationFailure(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	res := &retryResolver{}
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-2": {
				ID:     "GO-TEST-2",
				Module: "example.com/dep",
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"Parse"},
				}},
			},
		}},
		VulnID:      "GO-TEST-2",
		Resolver:    stubResolver{},
		RCResolver:  res,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`)},
		UseSource:   true,
	})
	if !res.proposed {
		t.Fatal("Propose was never called despite verification failure")
	}
	if c.RootCause == nil || c.RootCause.Status != domain.RootCauseResolved {
		t.Fatalf("root cause=%+v", c.RootCause)
	}
	if len(c.RootCause.RootCauses) != 1 || c.RootCause.RootCauses[0].Symbol != "Parse" {
		t.Fatalf("root causes=%+v", c.RootCause.RootCauses)
	}
}

// Pattern-library golden: the advisory names a credential carrier, not an
// input->sink path. Classified INFO_LEAK, the model is C-DATA-PRESENT +
// C-EXPOSED; with no product reader the pair resolves to a verified FALSE
// -> NO_EXPLOIT_PATH_FOUND.
func TestE2EInfoLeakNoReader(t *testing.T) {
	repo := initRepoFrom(t, "leakprod")
	caseDir := t.TempDir()

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-LEAK-1": {
				ID:      "GO-LEAK-1",
				Module:  "example.com/dep",
				Summary: "credentials retained in plaintext in exported struct fields",
				// The pattern library's class comes from the record's own
				// structured CWE ids; prose vocabulary is a nomination. CWE-200
				// (exposure of sensitive information) is the class this
				// synthetic advisory carries, so the INFO_LEAK pattern is
				// selected by structured data.
				CWE:   []string{"CWE-200"},
				Scope: exactScopeFor("GO-LEAK-1", "example.com/dep"),
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"PlainAuth.Password"},
				}},
			},
		}},
		VulnID:   "GO-LEAK-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "PlainAuth.Password", Role: domain.RootCauseSink,
		}},
		CaseDir:         caseDir,
		Govulncheck:     fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})

	if c.Exploit == nil || c.Exploit.Class != "INFO_LEAK" {
		t.Fatalf("exploit class=%v, want INFO_LEAK", c.Exploit)
	}
	present := findClaimT(t, c.Claims, "C-DATA-PRESENT")
	if present.Result != domain.ClaimTrue {
		t.Fatalf("C-DATA-PRESENT=%s want TRUE (%s)", present.Result, present.Explanation)
	}
	exposed := findClaimT(t, c.Claims, "C-EXPOSED")
	if exposed.Result != domain.ClaimFalse {
		t.Fatalf("C-EXPOSED=%s want FALSE (%s)", exposed.Result, exposed.Explanation)
	}
	if exposed.NegativeVerification == nil ||
		exposed.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("neg verification=%+v want VERIFIED", exposed.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

// Same INFO_LEAK model, but the product reads the exported credential
// field: both pattern conditions are TRUE -> EXPLOITABLE.
func TestE2EInfoLeakReader(t *testing.T) {
	repo := initRepoFrom(t, "leakread")
	caseDir := t.TempDir()

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-LEAK-2": {
				ID:      "GO-LEAK-2",
				Module:  "example.com/dep",
				Summary: "credentials retained in plaintext in exported struct fields",
				// Structured class data, as in the no-reader control: the
				// INFO_LEAK pattern is selected from the record's CWE, never
				// from its prose.
				CWE: []string{"CWE-200"},
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"PlainAuth.Password"},
				}},
			},
		}},
		VulnID:   "GO-LEAK-2",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "PlainAuth.Password", Role: domain.RootCauseSink,
		}},
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`)},
		UseSource:   true,
	})

	exposed := findClaimT(t, c.Claims, "C-EXPOSED")
	if exposed.Result != domain.ClaimTrue {
		t.Fatalf("C-EXPOSED=%s want TRUE (%s)", exposed.Result, exposed.Explanation)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// TLS knob, insecure side: tlsprod assigns crypto/tls
// Config.InsecureSkipVerify=true. The knob used to arrive as the C-TLS-VERIFY
// supporting condition of the peer-gated RESOURCE_EXHAUSTION/OOB_WRITE
// variant, which was eligible only while a prose regex made "peer" the
// authoritative input route. AdvisoryInputRoute now returns the unresolved
// route for every advisory (no OSV field binds the route), so no route-gated
// variant is selected and no configuration condition exists. This test pins
// that honest outcome — an insecure knob in the product decides nothing when
// no established route makes it a condition — and keeps the knob's own
// evaluator contract in internal/evaluator/configflag_test.go.
func TestE2ETLSKnobInsecure(t *testing.T) {
	repo := initRepoFrom(t, "tlsprod")
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-WIRE-1": {
				ID:      "GO-WIRE-1",
				Module:  "example.com/dep",
				Summary: "wire protocol parser buffer overflow when a remote peer sends a malformed frame",
				CWE:     []string{"CWE-787"},
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"Parse"},
				}},
			},
		}},
		VulnID:   "GO-WIRE-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink,
		}},
		CaseDir:     t.TempDir(),
		Govulncheck: fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`)},
		UseSource:   true,
	})
	assertNoTLSKnobCondition(t, c, "tlsprod")
}

// TLSSafe is the same advisory against a product that never sets the knob. Its
// absence used to make C-TLS-VERIFY a FALSE candidate that negative
// verification demoted to INSUFFICIENT_SCOPE. With no configuration condition
// in the model there is no claim to demote — and, importantly, the absent knob
// is not read as a safe answer.
func TestE2ETLSKnobSafe(t *testing.T) {
	repo := initRepoFrom(t, "tlssafe")
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-WIRE-2": {
				ID:      "GO-WIRE-2",
				Module:  "example.com/dep",
				Summary: "wire protocol parser buffer overflow when a remote peer sends a malformed frame",
				CWE:     []string{"CWE-787"},
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"Parse"},
				}},
			},
		}},
		VulnID:   "GO-WIRE-2",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink,
		}},
		CaseDir:         t.TempDir(),
		Govulncheck:     fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}`)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})
	assertNoTLSKnobCondition(t, c, "tlssafe")
}

// assertNoTLSKnobCondition pins the shared honest outcome of both TLS controls:
// the class is the record's own CWE-derived OOB_WRITE, the prose peer route is
// recorded as a nomination only, no configuration condition (the knob) is
// merged, and the unmodeled knob cannot decide a safe or a positive verdict.
func assertNoTLSKnobCondition(t *testing.T, c *domain.AnalysisCase, fixture string) {
	t.Helper()
	if c.Exploit == nil {
		t.Fatal("no exploit model was built")
	}
	if c.Exploit.Class != "OOB_WRITE" {
		t.Fatalf("class=%q, want the record's own CWE-787 class OOB_WRITE", c.Exploit.Class)
	}
	if c.Exploit.InputRoute != "" {
		t.Fatalf("input route=%q, want the unestablished route", c.Exploit.InputRoute)
	}
	var routeNominated bool
	for _, n := range c.Exploit.MechanismNominations {
		if n.Kind == domain.MechanismNominationInputRoute && n.Value == "peer" &&
			n.Source == domain.MechanismNominationProse {
			routeNominated = true
		}
	}
	if !routeNominated {
		t.Fatalf("the prose peer route was not even nominated for %s: %+v", fixture, c.Exploit.MechanismNominations)
	}
	for _, cond := range append(append([]domain.Condition{}, c.Exploit.MandatoryConditions...), c.Exploit.SupportingFactors...) {
		if cond.ID == "C-TLS-VERIFY" || cond.Kind == domain.ConditionConfiguration {
			t.Fatalf("configuration condition %s survives without an established route: %+v", cond.ID, cond)
		}
		if cond.Params[domain.ParamInputSource] == domain.InputPeer || cond.Params["protocol_role"] != "" {
			t.Fatalf("condition %s claims a peer/protocol fact from prose: %+v", cond.ID, cond.Params)
		}
	}
	for _, claim := range c.Claims {
		if claim.ConditionID == "C-TLS-VERIFY" {
			t.Fatalf("a TLS knob claim exists without a condition: %+v", claim)
		}
	}
	if c.Verdict != nil {
		switch c.Verdict.Verdict {
		case domain.VerdictExploitable, domain.VerdictNoExploitPathFound, domain.VerdictNotAffected:
			t.Fatalf("%s published the knob-dependent verdict %s; the unmodeled knob decides nothing",
				fixture, c.Verdict.Verdict)
		}
	}
}

// Caller-frame validation: the sink frame has no guard, but the only
// caller validates the argument before the call. GAP_ANALYSIS climbs the
// caller chain, records a sink-covering guard, and VALIDATION goes FALSE.
func TestE2ECallerFrameGuard(t *testing.T) {
	repo := initRepoFrom(t, "guardprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0},
		{"id":"C-VALID","kind":"VALIDATION","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": exactTestVuln(),
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:    mp,
		CaseDir:  filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","trace":[
 {"package":"example.com/guardprod","function":"sink","position":{"filename":"main.go","line":11}},
 {"package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})

	cl := findClaimT(t, c.Claims, "C-VALID")
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("C-VALID=%s want FALSE via caller-frame guard (%s; lims=%v)",
			cl.Result, cl.Explanation, cl.Limitations)
	}
	var cover bool
	for _, v := range c.EvidenceGraph.Validations {
		if v.Covers != nil {
			cover = true
		}
	}
	if !cover {
		t.Fatal("expected a Covers= validation marking caller-frame coverage")
	}
	var hyp *domain.Hypothesis
	for i := range c.Hypotheses {
		if c.Hypotheses[i].ConditionID == "C-VALID" {
			hyp = &c.Hypotheses[i]
		}
	}
	if hyp == nil || hyp.Status != domain.HypothesisConfirmed {
		t.Fatalf("hypothesis=%+v want CONFIRMED", hyp)
	}
	if cl.NegativeVerification == nil ||
		cl.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("neg verification=%+v want VERIFIED", cl.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

// Partial caller coverage must NOT justify FALSE: one caller guards, the
// other does not — VALIDATION stays UNKNOWN, verdict INCONCLUSIVE.
func TestE2EPartialCallerGuardStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "mixguard")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0},
		{"id":"C-VALID","kind":"VALIDATION","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:    mp,
		CaseDir:  filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","trace":[
 {"package":"example.com/mixguard","function":"sink","position":{"filename":"main.go","line":10}},
 {"package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`)},
		UseSource: true,
	})

	cl := findClaimT(t, c.Claims, "C-VALID")
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("C-VALID=%s want UNKNOWN on partial caller coverage (%s)", cl.Result, cl.Explanation)
	}
	for _, v := range c.EvidenceGraph.Validations {
		if v.Covers != nil {
			t.Fatalf("partial coverage must not emit Covers= validation: %+v", v)
		}
	}
	requireAssessmentFailed(t, c, domain.GapUnclassifiedAnalysisGap)
}

// The REVIEW->REPAIR->REVIEW loop converges: the demoted claim resolves
// the high-severity finding, the second review ACCEPTs, and the case
// proceeds to the verdict computed on the repaired claim set.
func TestReviewRepairLoopConverges(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{ID: "C-1", Kind: domain.ConditionSymbolReachable}},
		},
		RootCause: &domain.RootCauseModel{Status: domain.RootCauseResolved},
		Claims: []domain.Claim{{
			ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue,
		}},
	}
	h := states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}}
	rp := states.RepairAnalysis{}

	tr, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateRepairAnalysis {
		t.Fatalf("next=%s want REPAIR_ANALYSIS", tr.Next)
	}
	tr, err = rp.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next=%s want re-REVIEW", tr.Next)
	}
	tr, err = h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT after ACCEPT", tr.Next)
	}
	if len(c.Reviews) != 2 || c.Reviews[1].Result != domain.ReviewAccept {
		t.Fatalf("second review should accept the repaired claim set: %+v", c.Reviews)
	}
}

// TestReviewActionAloneCannotPromoteSupporting pins the promote boundary: a
// review nomination is recorded but never applied. No deterministic contract
// proves necessity, and an empty applicability result is not proof, so the
// supporting factor stays supporting and the all-TRUE conjunction keeps its
// EXPLOITABLE truth.
func TestReviewActionAloneCannotPromoteSupporting(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{ID: "C-1", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
			SupportingFactors: []domain.Condition{{
				ID: "C-XDS-SERVER", Kind: domain.ConditionConfiguration,
				Description: "xDS server initialization",
			}},
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Claims: []domain.Claim{{ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue}},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{{
				Severity:   "high",
				TargetType: "condition",
				TargetID:   "C-XDS-SERVER",
				Action:     domain.ReviewActionPromote,
				Problem:    "xDS server initialization required for crash",
			}},
		}},
	}
	tr, err := (states.RepairAnalysis{}).Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT: a promote nomination is not a repair", tr.Next)
	}
	if len(c.Exploit.MandatoryConditions) != 1 || c.Exploit.MandatoryConditions[0].ID != "C-1" {
		t.Fatalf("promote nomination changed the conjunction: %+v", c.Exploit.MandatoryConditions)
	}
	if len(c.Exploit.SupportingFactors) != 1 ||
		c.Exploit.SupportingFactors[0].ID != "C-XDS-SERVER" ||
		c.Exploit.SupportingFactors[0].Mandatory {
		t.Fatalf("supporting factor was moved by a nomination: %+v", c.Exploit.SupportingFactors)
	}
	if len(c.Exploit.PendingConditionReviews) != 0 {
		t.Fatalf("a promote nomination must not create a pending review: %v", c.Exploit.PendingConditionReviews)
	}
	lims := strings.Join(c.EvidenceGraph.Limitations, "\n")
	for _, want := range []string{"C-XDS-SERVER", "not applied", "no deterministic necessity proof"} {
		if !strings.Contains(lims, want) {
			t.Fatalf("promote limitation %q does not name %q", lims, want)
		}
	}
	got := evalCaseVerdict(c, c.Claims)
	if got.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%s (%s), want EXPLOITABLE: a promote nomination cannot narrow evaluated truth",
			got.Verdict, got.Reason)
	}
}

// verifiedPlatformFalse is the snapshot fact the reviewer must not
// rewrite: a VERIFIED FALSE claim with a falsifier and evidence.
func verifiedPlatformFalse() domain.Claim {
	return domain.Claim{
		ID:          "CL-PLATFORM",
		ConditionID: "C-PLATFORM",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
		EvidenceIDs: []domain.EvidenceID{"EV-PLATFORM"},
		NegativeVerification: &domain.NegativeVerification{
			Status:      domain.NegativeVerified,
			EvidenceIDs: []domain.EvidenceID{"EV-PLATFORM-NV"},
			Notes:       "release toolchain resolves above the floor",
		},
	}
}

func hasConditionID(conds []domain.Condition, id domain.ConditionID) bool {
	return conditionByID(conds, id) != nil
}

func conditionByID(conds []domain.Condition, id domain.ConditionID) *domain.Condition {
	for i := range conds {
		if conds[i].ID == id {
			return &conds[i]
		}
	}
	return nil
}

func countCondition(conds []domain.Condition, id domain.ConditionID) int {
	n := 0
	for _, cond := range conds {
		if cond.ID == id {
			n++
		}
	}
	return n
}

func hasPendingCondition(c *domain.AnalysisCase, id domain.ConditionID) bool {
	for _, pending := range c.Exploit.PendingConditionReviews {
		if pending == id {
			return true
		}
	}
	return false
}

// TestReviewActionAloneCannotDemoteMandatory pins the demote boundary on a
// verified-negative baseline: a reviewer's demote nomination is not an
// independently established repair. Without a deterministic applicability
// mismatch the condition stays mandatory, its VERIFIED FALSE claim is
// untouched, and the unproven critique remains pending so no verdict closes
// around it.
func TestReviewActionAloneCannotDemoteMandatory(t *testing.T) {
	verified := domain.Claim{
		ID:          "CL-C-REACH",
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
		EvidenceIDs: []domain.EvidenceID{"EV-REACH"},
		NegativeVerification: &domain.NegativeVerification{
			Status:      domain.NegativeVerified,
			EvidenceIDs: []domain.EvidenceID{"EV-REACH-NV"},
			Notes:       "reachability falsifier re-checked",
		},
	}
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
			}},
		},
		Claims: []domain.Claim{verified},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{{
				TargetType: "condition", TargetID: "C-REACH",
				Action: domain.ReviewActionDemote, Severity: "high",
				Problem: "reachability condition is not a prerequisite of this advisory",
			}},
		}},
	}
	tr, err := (states.RepairAnalysis{}).Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT: an unproven demote is not a repair", tr.Next)
	}
	if !hasConditionID(c.Exploit.MandatoryConditions, "C-REACH") {
		t.Fatalf("review nomination removed the mandatory condition: %+v", c.Exploit.MandatoryConditions)
	}
	if hasConditionID(c.Exploit.SupportingFactors, "C-REACH") {
		t.Fatalf("review nomination moved the condition to supporting: %+v", c.Exploit.SupportingFactors)
	}
	if !hasPendingCondition(c, "C-REACH") {
		t.Fatalf("unestablished demote must stay pending: %v", c.Exploit.PendingConditionReviews)
	}
	if !reflect.DeepEqual(c.Claims[0], verified) {
		t.Fatalf("demote nomination changed the verified claim:\n got %+v\nwant %+v", c.Claims[0], verified)
	}
	lims := strings.Join(c.EvidenceGraph.Limitations, "\n")
	for _, want := range []string{"C-REACH", "REV-1", "no deterministic applicability mismatch"} {
		if !strings.Contains(lims, want) {
			t.Fatalf("limitation %q does not name %q", lims, want)
		}
	}
	got := evalCaseVerdict(c, c.Claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%s (%s), want INCONCLUSIVE while the critique is pending", got.Verdict, got.Reason)
	}
	if len(got.ConditionIDs) != 1 || got.ConditionIDs[0] != "C-REACH" {
		t.Fatalf("verdict condition ids=%v want C-REACH", got.ConditionIDs)
	}
}

// A demotion is applied only when the deterministic applicability contract
// names a concrete mismatch: C-PLATFORM moves to supporting, while its
// claim, falsifier, negative verification and evidence stay byte-for-byte
// intact.
func TestRepairDemotesIrrelevantMandatoryCondition(t *testing.T) {
	before := verifiedPlatformFalse()
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
				{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true},
				{ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true,
					Description: "legacy TLS floor",
					Params:      map[string]string{"go_version": "< 1.18"}},
			},
		},
		Claims: []domain.Claim{
			{ID: "CL-REACH", ConditionID: "C-REACH", Result: domain.ClaimUnknown},
			{ID: "CL-INPUT", ConditionID: "C-INPUT", Result: domain.ClaimUnknown},
			before,
		},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{{
				TargetType: "condition", TargetID: "C-PLATFORM",
				Action: domain.ReviewActionDemote, Severity: "high",
				Problem: "legacy TLS floor does not gate an SSH key-exchange downgrade",
			}},
		}},
	}
	tr, err := states.RepairAnalysis{}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next=%s want re-REVIEW after demotion", tr.Next)
	}
	if hasConditionID(c.Exploit.MandatoryConditions, "C-PLATFORM") {
		t.Fatalf("C-PLATFORM must leave the mandatory conjunction: %+v", c.Exploit.MandatoryConditions)
	}
	if n := countCondition(c.Exploit.SupportingFactors, "C-PLATFORM"); n != 1 {
		t.Fatalf("C-PLATFORM supporting occurrences=%d want exactly 1: %+v", n, c.Exploit.SupportingFactors)
	}
	plat := conditionByID(c.Exploit.SupportingFactors, "C-PLATFORM")
	if plat == nil || plat.Mandatory {
		t.Fatalf("demoted condition must be non-mandatory: %+v", plat)
	}
	if !reflect.DeepEqual(c.Claims[2], before) {
		t.Fatalf("demotion changed the verified claim record:\n got %+v\nwant %+v", c.Claims[2], before)
	}
	lim := strings.Join(c.EvidenceGraph.Limitations, "\n")
	for _, want := range []string{"C-PLATFORM", "REV-1", "legacy TLS floor does not gate"} {
		if !strings.Contains(lim, want) {
			t.Fatalf("limitation %q does not name %q", lim, want)
		}
	}
	got := evalCaseVerdict(c, c.Claims)
	if got.Verdict == domain.VerdictNoExploitPathFound {
		t.Fatalf("recomputed verdict still grounds NEPF on the demoted condition: %+v", got)
	}
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("recomputed verdict=%s want INCONCLUSIVE", got.Verdict)
	}
	if strings.Contains(got.Reason, "C-PLATFORM") {
		t.Fatalf("verdict reason still uses C-PLATFORM: %q", got.Reason)
	}
}

// Demoting the last mandatory condition leaves an empty conjunction: the
// case must stay INCONCLUSIVE rather than inherit the old false-safe.
func TestRepairDemotesSoleMandatoryCondition(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true,
				Description: "legacy TLS floor",
				Params:      map[string]string{"go_version": "<1.18"},
			}},
		},
		Claims: []domain.Claim{verifiedPlatformFalse()},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{{
				TargetType: "condition", TargetID: "C-PLATFORM",
				Action: domain.ReviewActionDemote, Severity: "high",
				Problem: "condition is not a prerequisite of the advisory mechanism",
			}},
		}},
	}
	tr, err := states.RepairAnalysis{}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next=%s want re-REVIEW", tr.Next)
	}
	if len(c.Exploit.MandatoryConditions) != 0 {
		t.Fatalf("mandatory conjunction must be empty: %+v", c.Exploit.MandatoryConditions)
	}
	if n := countCondition(c.Exploit.SupportingFactors, "C-PLATFORM"); n != 1 {
		t.Fatalf("demoted condition supporting occurrences=%d want 1", n)
	}
	got := evalCaseVerdict(c, c.Claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("empty-after-demotion verdict=%s want INCONCLUSIVE (old false-safe must not survive)", got.Verdict)
	}
}

// A repeated deterministically-established demotion is a no-op: supporting
// factors do not duplicate and the mandatory conjunction stays empty.
func TestRepairConditionActionsAreIdempotent(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-M", Kind: domain.ConditionPlatform, Mandatory: true,
				Description: "legacy TLS floor",
				Params:      map[string]string{"go_version": "<1.18"},
			}},
		},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{{
				TargetType: "condition", TargetID: "C-M",
				Action: domain.ReviewActionDemote, Severity: "high",
				Problem: "irrelevant condition",
			}},
		}},
	}
	rp := states.RepairAnalysis{}
	if _, err := rp.Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Reviews = append(c.Reviews, domain.Review{
		ID: "REV-2", Result: domain.ReviewRevise,
		Findings: []domain.ReviewFinding{{
			TargetType: "condition", TargetID: "C-M",
			Action: domain.ReviewActionDemote, Severity: "high",
			Problem: "still irrelevant",
		}},
	})
	tr, err := rp.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT when nothing changed", tr.Next)
	}
	if hasConditionID(c.Exploit.MandatoryConditions, "C-M") {
		t.Fatalf("C-M returned to the mandatory conjunction")
	}
	if n := countCondition(c.Exploit.SupportingFactors, "C-M"); n != 1 {
		t.Fatalf("C-M supporting occurrences=%d want exactly 1", n)
	}
}

// Conflicting condition actions on an already-supporting factor are
// nominations only: neither a promote nor a demote moves it, in either
// finding order.
func TestRepairConditionActionConflictLeavesSupporting(t *testing.T) {
	promote := domain.ReviewFinding{
		TargetType: "condition", TargetID: "C-M",
		Action: domain.ReviewActionPromote, Severity: "high",
		Problem: "reviewer thinks the condition is necessary",
	}
	demote := domain.ReviewFinding{
		TargetType: "condition", TargetID: "C-M",
		Action: domain.ReviewActionDemote, Severity: "high",
		Problem: "reviewer thinks the condition is irrelevant",
	}
	for _, tc := range []struct {
		name     string
		findings []domain.ReviewFinding
	}{
		{"promote before demote", []domain.ReviewFinding{promote, demote}},
		{"demote before promote", []domain.ReviewFinding{demote, promote}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &domain.AnalysisCase{
				Exploit: &domain.ExploitModel{
					SupportingFactors: []domain.Condition{{
						ID: "C-M", Kind: domain.ConditionPlatform,
					}},
				},
				Reviews: []domain.Review{{
					ID: "REV-1", Result: domain.ReviewRevise, Findings: tc.findings,
				}},
			}
			if _, err := (states.RepairAnalysis{}).Run(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			if hasConditionID(c.Exploit.MandatoryConditions, "C-M") {
				t.Fatalf("a promote nomination promoted a supporting factor: mandatory=%+v", c.Exploit.MandatoryConditions)
			}
			if n := countCondition(c.Exploit.SupportingFactors, "C-M"); n != 1 {
				t.Fatalf("C-M supporting occurrences=%d want 1", n)
			}
			if cond := conditionByID(c.Exploit.SupportingFactors, "C-M"); cond == nil || cond.Mandatory {
				t.Fatalf("conflicted condition must stay non-mandatory supporting: %+v", cond)
			}
		})
	}
}

// Once the deterministic applicability contract demoted a condition, a
// later promote nomination without new evidence may not put it back into
// the conjunction.
func TestRepairDoesNotRepromotePreviouslyDemotedCondition(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
				{ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true,
					Description: "legacy TLS floor",
					Params:      map[string]string{"go_version": "<1.18"}},
			},
		},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{{
				TargetType: "condition", TargetID: "C-PLATFORM",
				Action: domain.ReviewActionDemote, Severity: "high",
				Problem: "legacy TLS floor is not part of the SSH downgrade mechanism",
			}},
		}},
	}
	rp := states.RepairAnalysis{}
	if _, err := rp.Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Reviews = append(c.Reviews, domain.Review{
		ID: "REV-2", Result: domain.ReviewRevise,
		Findings: []domain.ReviewFinding{{
			TargetType: "condition", TargetID: "C-PLATFORM",
			Action: domain.ReviewActionPromote, Severity: "high",
			Problem: "condition now looks necessary",
		}},
	})
	tr, err := rp.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT: the stale promote is not a repair", tr.Next)
	}
	if hasConditionID(c.Exploit.MandatoryConditions, "C-PLATFORM") {
		t.Fatalf("previously demoted condition returned to the conjunction: %+v", c.Exploit.MandatoryConditions)
	}
	if n := countCondition(c.Exploit.SupportingFactors, "C-PLATFORM"); n != 1 {
		t.Fatalf("C-PLATFORM supporting occurrences=%d want 1", n)
	}
}

// Wrong targets, medium severities and non-condition targets never mutate
// conditions or claims.
func TestRepairConditionWrongTargetOrMediumSeverity(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-M", Kind: domain.ConditionPlatform, Mandatory: true,
			}},
			SupportingFactors: []domain.Condition{{
				ID: "C-S", Kind: domain.ConditionConfiguration,
			}},
		},
		Claims: []domain.Claim{{ID: "CL-M", ConditionID: "C-M", Result: domain.ClaimTrue}},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{
				{TargetType: "condition", TargetID: "C-UNKNOWN", Action: domain.ReviewActionDemote,
					Severity: "high", Problem: "target does not exist"},
				{TargetType: "condition", TargetID: "C-M", Action: domain.ReviewActionDemote,
					Severity: "medium", Problem: "medium severity must not mutate"},
				{TargetType: "condition", TargetID: "C-S", Action: domain.ReviewActionPromote,
					Severity: "medium", Problem: "medium severity must not mutate"},
				{TargetType: "claim", TargetID: "CL-M", Severity: "medium",
					Problem: "medium severity must not demote a claim"},
			},
		}},
	}
	tr, err := states.RepairAnalysis{}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT with nothing repairable", tr.Next)
	}
	if !hasConditionID(c.Exploit.MandatoryConditions, "C-M") {
		t.Fatalf("C-M left the mandatory conjunction: %+v", c.Exploit.MandatoryConditions)
	}
	if hasConditionID(c.Exploit.MandatoryConditions, "C-S") {
		t.Fatalf("C-S was promoted by a medium finding: %+v", c.Exploit.MandatoryConditions)
	}
	if !hasConditionID(c.Exploit.SupportingFactors, "C-S") {
		t.Fatalf("C-S left supporting factors: %+v", c.Exploit.SupportingFactors)
	}
	if len(c.Exploit.PendingConditionReviews) != 0 {
		t.Fatalf("pending reviews must stay empty: %v", c.Exploit.PendingConditionReviews)
	}
	if c.Claims[0].Result != domain.ClaimTrue {
		t.Fatalf("medium claim finding mutated the claim: %+v", c.Claims[0])
	}
}

// A high condition finding without a supported action is recorded as a
// pending review: the verdict must be INCONCLUSIVE, not a safe closure
// carrying a caveat.
func TestRepairConditionActionlessMandatoryBlocksClosure(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
				{ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true},
			},
		},
		Claims: []domain.Claim{
			// Without the pending gate this verified FALSE would ground NEPF.
			verifiedPlatformFalse(),
		},
		Reviews: []domain.Review{{
			ID: "REV-1", Result: domain.ReviewRevise,
			Findings: []domain.ReviewFinding{{
				TargetType: "condition", TargetID: "C-PLATFORM", Severity: "high",
				Problem: "condition may be irrelevant to this advisory",
			}},
		}},
	}
	tr, err := states.RepairAnalysis{}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT", tr.Next)
	}
	if !hasPendingCondition(c, "C-PLATFORM") {
		t.Fatalf("actionless high condition finding was dropped: %v", c.Exploit.PendingConditionReviews)
	}
	got := evalCaseVerdict(c, c.Claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%s want INCONCLUSIVE while the critique is pending", got.Verdict)
	}
	if len(got.ConditionIDs) != 1 || got.ConditionIDs[0] != "C-PLATFORM" {
		t.Fatalf("verdict condition ids=%v want C-PLATFORM", got.ConditionIDs)
	}
}

// demoteOnceReviewer requests one explicit condition demotion while the
// target is mandatory, then accepts the repaired package.
type demoteOnceReviewer struct {
	target  domain.ConditionID
	problem string
}

func (r demoteOnceReviewer) Review(c *domain.AnalysisCase, _ domain.VerdictResult) domain.Review {
	if c.Exploit != nil {
		for _, cond := range c.Exploit.MandatoryConditions {
			if cond.ID == r.target {
				return domain.Review{
					Result: domain.ReviewRevise,
					Findings: []domain.ReviewFinding{{
						TargetType: "condition", TargetID: string(r.target),
						Action: domain.ReviewActionDemote, Severity: "high",
						Problem: r.problem,
					}},
				}
			}
		}
	}
	return domain.Review{Result: domain.ReviewAccept}
}

// The bounded REVIEW->REPAIR->REVIEW loop converges after an explicit
// condition demotion: the second review accepts the repaired package, the
// demoted condition stays out of the conjunction and the review budget is
// unchanged.
func TestReviewRepairConditionLoopConverges(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
				{ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true,
					Description: "legacy TLS floor",
					Params:      map[string]string{"go_version": "<1.18"}},
			},
		},
		Claims: []domain.Claim{{ID: "CL-REACH", ConditionID: "C-REACH", Result: domain.ClaimUnknown}},
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{MaxReviewIterations: 2},
		},
	}
	h := states.Review{
		Reviewer: demoteOnceReviewer{
			target:  "C-PLATFORM",
			problem: "legacy TLS floor is not a prerequisite of the SSH downgrade",
		},
		Evaluator: evaluator.VerdictEvaluator{},
	}
	rp := states.RepairAnalysis{}

	tr, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateRepairAnalysis {
		t.Fatalf("next=%s want REPAIR_ANALYSIS", tr.Next)
	}
	tr, err = rp.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next=%s want re-REVIEW", tr.Next)
	}
	tr, err = h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT after the repaired package is accepted", tr.Next)
	}
	if len(c.Reviews) != 2 || c.Reviews[1].Result != domain.ReviewAccept {
		t.Fatalf("second review should accept the repaired package: %+v", c.Reviews)
	}
	if c.Workflow.Limits.MaxReviewIterations != 2 {
		t.Fatalf("repair must not raise MaxReviewIterations: %d", c.Workflow.Limits.MaxReviewIterations)
	}
	if hasConditionID(c.Exploit.MandatoryConditions, "C-PLATFORM") {
		t.Fatalf("demoted condition returned to the conjunction: %+v", c.Exploit.MandatoryConditions)
	}
	if n := countCondition(c.Exploit.SupportingFactors, "C-PLATFORM"); n != 1 {
		t.Fatalf("C-PLATFORM supporting occurrences=%d want 1", n)
	}
	if !strings.Contains(strings.Join(c.EvidenceGraph.Limitations, "\n"), "REV-1") {
		t.Fatalf("demotion limitation must cite the structured review id: %v", c.EvidenceGraph.Limitations)
	}
	if c.Verdict != nil {
		t.Fatalf("repair must not set the verdict: %+v", c.Verdict)
	}
	got := evalCaseVerdict(c, c.Claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("recomputed verdict=%s want INCONCLUSIVE", got.Verdict)
	}
}

// A VERIFIED FALSE falls only to a finding that cites a concrete
// counterexample artifact already present in the claim's own record
// (dynamic marker, uncovered site, traced origin, linked evidence) — or
// to a structural defect like a dangling evidence reference. A semantic
// reinterpretation — e.g. the twice-observed "contradicts the root
// cause" misread — or a merely proposed check is downgraded to advisory
// and the deterministic negative stands.
func TestRepairVerifiedFalseArtifactGate(t *testing.T) {
	cases := []struct {
		name     string
		nv       *domain.NegativeVerification
		prob     string
		req      string
		findings []domain.ReviewFinding // replaces the single prob/req finding when set
		setup    func(c *domain.AnalysisCase, cl *domain.Claim)
		want     domain.ClaimResult
		wantV    bool // want a "reviewer concern" advisory on the claim
	}{
		{name: "semantic misread keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "FALSE claim contradicts the root cause mechanism",
			want: domain.ClaimFalse, wantV: true},
		{name: "bare english word keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "the conclusion is unsafe to rely on",
			want: domain.ClaimFalse, wantV: true},
		{name: "proposed check keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "sink argument may be peer-controlled",
			req:  "trace the sink argument to EXTERNAL_UNTRUSTED origin",
			want: domain.ClaimFalse, wantV: true},
		{name: "marker named but never recorded keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "func_value marker lets the symbol escape the static call graph",
			want: domain.ClaimFalse, wantV: true},
		{name: "dismissed linkname keeps FALSE",
			nv: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Notes: "all 1 call site(s) across 1 subject(s) pass non-external input;" +
					" 1 unrelated go:linkname pragma(s) ignored",
				EvidenceIDs: []domain.EvidenceID{"EV-001"},
			},
			prob: "the go:linkname pragma at link.go:9 provides a path to the symbol",
			setup: func(c *domain.AnalysisCase, _ *domain.Claim) {
				c.EvidenceGraph.AddEvidence(domain.Evidence{
					ID: "EV-001", Kind: domain.EvidenceSourceSnippet,
					Source:  "go-analysis ScanDynamic",
					Content: "linkname at link.go:9: //go:linkname local upstream/pkg.handler",
				})
			},
			want: domain.ClaimFalse, wantV: true},
		{name: "recorded marker limitation demotes",
			nv: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Limitations: []string{
					"reflect usage in product widens the call graph; static negative verification is weaker",
				},
			},
			prob: "reflect usage in product widens the call graph; static negative verification is weaker",
			want: domain.ClaimUnknown},
		{name: "site named but never recorded keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "uncovered write site at server.go:41 reaches the guarded field",
			want: domain.ClaimFalse, wantV: true},
		{name: "marker site demotes",
			nv: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Limitations: []string{
					"reflect.Value.Set* call at /repo/server.go:41 can write fields invisibly; guard coverage is weaker",
				},
			},
			prob: "uncovered write site at server.go:41 reaches the guarded field",
			want: domain.ClaimUnknown},
		{name: "recorded site suffix demotes",
			nv: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Limitations: []string{
					"reflect.Value.Set* call at /repo/server.go:41 can write fields invisibly; guard coverage is weaker",
				},
			},
			prob: "uncovered write site at /repo/server.go:41 reaches the guarded field",
			want: domain.ClaimUnknown},
		{name: "backtick-quoted site demotes",
			nv: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Limitations: []string{
					"reflect.Value.Set* call at server.go:41 can write fields invisibly; guard coverage is weaker",
				},
			},
			prob: "uncovered write site at `server.go:41` reaches the guarded field",
			want: domain.ClaimUnknown},
		{name: "covered site keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "uncovered write site at server.go:41 reaches the guarded field",
			setup: func(c *domain.AnalysisCase, _ *domain.Claim) {
				c.EvidenceGraph.AddDataFlows(domain.DataFlow{
					ConditionID: "C-1",
					Sink:        domain.CallSite{File: "server.go", Line: 41},
				})
				c.EvidenceGraph.AddValidations(domain.Validation{
					CallSite: domain.CallSite{File: "guard.go", Line: 12},
					Property: "cond=C-1 bound", Guard: true,
					Covers: &domain.CallSite{File: "server.go", Line: 41},
				})
			},
			want: domain.ClaimFalse, wantV: true},
		{name: "line-prefix site keeps FALSE",
			nv: &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Limitations: []string{
					"reflect.Value.Set* call at /repo/server.go:410 can write fields invisibly; guard coverage is weaker",
				},
			},
			prob: "uncovered write site at server.go:41 reaches the guarded field",
			want: domain.ClaimFalse, wantV: true},
		{name: "origin named but never traced keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "the sink argument traces to EXTERNAL_UNTRUSTED input",
			want: domain.ClaimFalse, wantV: true},
		{name: "recorded external origin demotes",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "the sink argument traces to EXTERNAL_UNTRUSTED input",
			setup: func(c *domain.AnalysisCase, _ *domain.Claim) {
				c.EvidenceGraph.AddDataFlows(domain.DataFlow{
					ConditionID: "C-1",
					Origin:      domain.OriginExternalUntrusted,
				})
			},
			want: domain.ClaimUnknown},
		{name: "claim-linked evidence id demotes",
			nv: &domain.NegativeVerification{
				Status:      domain.NegativeVerified,
				EvidenceIDs: []domain.EvidenceID{"EV-001"},
			},
			prob: "EV-001 shows the sink argument is peer-controlled",
			setup: func(c *domain.AnalysisCase, _ *domain.Claim) {
				c.EvidenceGraph.AddEvidence(domain.Evidence{
					ID: "EV-001", Kind: domain.EvidenceSourceSnippet,
					Content: "traced flow",
				})
			},
			want: domain.ClaimUnknown},
		{name: "evidence id mentioned in explanation keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "EV-001 shows the sink argument is peer-controlled",
			setup: func(_ *domain.AnalysisCase, cl *domain.Claim) {
				cl.Explanation = "evaluator: guard coverage recorded under EV-001"
			},
			want: domain.ClaimFalse, wantV: true},
		{name: "unlinked evidence id keeps FALSE",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "EV-001 shows the sink argument is peer-controlled",
			setup: func(c *domain.AnalysisCase, _ *domain.Claim) {
				c.EvidenceGraph.AddEvidence(domain.Evidence{
					ID: "EV-001", Kind: domain.EvidenceSourceSnippet,
					Content: "unrelated record",
				})
			},
			want: domain.ClaimFalse, wantV: true},
		{name: "substring of another id keeps FALSE",
			nv: &domain.NegativeVerification{
				Status:      domain.NegativeVerified,
				EvidenceIDs: []domain.EvidenceID{"EV-001"},
			},
			prob: "EV-0010 shows the sink argument is peer-controlled",
			setup: func(c *domain.AnalysisCase, _ *domain.Claim) {
				c.EvidenceGraph.AddEvidence(domain.Evidence{
					ID: "EV-001", Kind: domain.EvidenceSourceSnippet,
					Content: "traced flow",
				})
			},
			want: domain.ClaimFalse, wantV: true},
		{name: "dangling claim evidence demotes",
			nv:   &domain.NegativeVerification{Status: domain.NegativeVerified},
			prob: "FALSE claim contradicts the root cause mechanism",
			setup: func(_ *domain.AnalysisCase, cl *domain.Claim) {
				cl.EvidenceIDs = []domain.EvidenceID{"EV-777"}
			},
			want: domain.ClaimUnknown},
		{name: "dangling verification evidence demotes",
			nv: &domain.NegativeVerification{
				Status:      domain.NegativeVerified,
				EvidenceIDs: []domain.EvidenceID{"EV-777"},
			},
			prob: "FALSE claim contradicts the root cause mechanism",
			want: domain.ClaimUnknown},
		{name: "unverified FALSE demotes without artifact",
			nv:   &domain.NegativeVerification{Status: domain.NegativeInsufficientScope},
			prob: "FALSE claim contradicts the root cause mechanism",
			want: domain.ClaimUnknown},
		{name: "FALSE without verification demotes without artifact",
			prob: "FALSE claim contradicts the root cause mechanism",
			want: domain.ClaimUnknown},
		{name: "repeated artifact-free finding keeps FALSE",
			nv: &domain.NegativeVerification{Status: domain.NegativeVerified},
			findings: []domain.ReviewFinding{
				{TargetType: "claim", TargetID: "CL-1", Severity: "high",
					Problem: "uncovered write site at server.go:41 reaches the guarded field"},
				{TargetType: "claim", TargetID: "CL-1", Severity: "high",
					Problem: "uncovered write site at server.go:41 reaches the guarded field"},
			},
			want: domain.ClaimFalse, wantV: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := tc.findings
			if findings == nil {
				findings = []domain.ReviewFinding{{
					TargetType: "claim", TargetID: "CL-1", Severity: "high",
					Problem: tc.prob, RequiredCheck: tc.req,
				}}
			}
			c := &domain.AnalysisCase{
				Claims: []domain.Claim{{
					ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimFalse,
					NegativeVerification: tc.nv,
				}},
				Reviews: []domain.Review{{
					Result: domain.ReviewRevise, Findings: findings,
				}},
			}
			if tc.setup != nil {
				tc.setup(c, &c.Claims[0])
			}
			tr, err := states.RepairAnalysis{}.Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if c.Claims[0].Result != tc.want {
				t.Fatalf("claim result=%s want %s", c.Claims[0].Result, tc.want)
			}
			concern := false
			for _, l := range c.Claims[0].Limitations {
				if strings.Contains(l, "reviewer concern") {
					concern = true
				}
			}
			if concern != tc.wantV {
				t.Fatalf("advisory concern recorded=%v want %v (limitations=%v)",
					concern, tc.wantV, c.Claims[0].Limitations)
			}
			if tc.want == domain.ClaimFalse && tr.Next != domain.StateEvaluateVerdict {
				t.Fatalf("kept claim must not loop to re-review, next=%s", tr.Next)
			}
		})
	}
}

// The structural reviewer must surface a dangling negative-verification
// evidence reference on the normal path — claimCitesMissingEvidence can
// only demote it once a review finding exists.
func TestStructuralDetectsDanglingVerificationEvidence(t *testing.T) {
	c := &domain.AnalysisCase{
		Claims: []domain.Claim{{
			ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimFalse,
			NegativeVerification: &domain.NegativeVerification{
				Status:      domain.NegativeVerified,
				EvidenceIDs: []domain.EvidenceID{"EV-777"},
			},
		}},
	}
	rev := review.Structural{}.Review(c, domain.VerdictResult{})
	if rev.Result != domain.ReviewRevise {
		t.Fatalf("structural review=%s want REVISE (findings=%v)", rev.Result, rev.Findings)
	}
	c.Reviews = append(c.Reviews, rev)
	if _, err := (states.RepairAnalysis{}).Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if c.Claims[0].Result != domain.ClaimUnknown {
		t.Fatalf("claim result=%s want UNKNOWN", c.Claims[0].Result)
	}
}

// Multi-step LLM planner: Plan is retried per iteration while it reports an
// attempted step, bounded by maxLLMPlanSteps per condition.
type countingPlanner struct {
	calls  int
	result bool
}

func (p *countingPlanner) Plan(_ context.Context, _ domain.Condition, _ *domain.AnalysisCase) bool {
	p.calls++
	return p.result
}

func TestGapLLMPlannerMultiStepBound(t *testing.T) {
	newCase := func() *domain.AnalysisCase {
		return &domain.AnalysisCase{
			Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{
				{ID: "C-RUNTIME", Kind: domain.ConditionRuntime, Mandatory: true},
			}},
			Claims: []domain.Claim{{ConditionID: "C-RUNTIME", Result: domain.ClaimUnknown}},
		}
	}

	// A planner that always finds more to do is capped at maxLLMPlanSteps.
	p := &countingPlanner{result: true}
	c := newCase()
	c.Workflow.Limits.MaxToolCalls = 0 // unlimited
	if _, err := (states.GapAnalysis{Source: &goanalysis.Index{Dir: t.TempDir()}, Planner: p}).Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if p.calls != 3 {
		t.Fatalf("planner calls=%d want %d (bounded per condition)", p.calls, 3)
	}

	// A planner that reports nothing actionable is asked exactly once.
	p2 := &countingPlanner{result: false}
	c2 := newCase()
	if _, err := (states.GapAnalysis{Source: &goanalysis.Index{Dir: t.TempDir()}, Planner: p2}).Run(context.Background(), c2); err != nil {
		t.Fatal(err)
	}
	if p2.calls != 1 {
		t.Fatalf("planner calls=%d want 1 (no retry on non-attempt)", p2.calls)
	}
}

// An authenticated outbound client produces EXTERNAL_AUTHENTICATED
// provenance — distinct from anonymous EXTERNAL_UNTRUSTED in the evidence,
// while still counting as attacker-capable input (authenticated peers can
// be malicious).
func TestE2EAuthenticatedClientOrigin(t *testing.T) {
	repo := initRepoFrom(t, "authprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/authprod","package":"example.com/authprod","function":"main","position":{"filename":"main.go","line":26}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawAuth bool
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.Origin == domain.OriginExternalAuthenticated {
			sawAuth = true
		}
	}
	if !sawAuth {
		t.Fatalf("no EXTERNAL_AUTHENTICATED flow recorded; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimTrue {
		t.Fatalf("C-INPUT=%s want TRUE (authenticated peer is still attacker-capable)", input.Result)
	}
}

// A security-relevant transform between source and sink is recorded in the
// DataFlow chain and surfaced as a claim limitation — never silently
// treated as a guard.
func TestE2ETransformationChainRecorded(t *testing.T) {
	repo := initRepoFrom(t, "escprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/escprod","package":"example.com/escprod","function":"main","position":{"filename":"main.go","line":14}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawEscape bool
	for _, f := range c.EvidenceGraph.DataFlows {
		for _, tx := range f.Transformations {
			if tx.Callee == "html.EscapeString" {
				sawEscape = true
			}
		}
	}
	if !sawEscape {
		t.Fatalf("html.EscapeString not recorded in transformations; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	var flagged bool
	for _, l := range input.Limitations {
		if strings.Contains(l, "EscapeString") {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("security-relevant transform not flagged; limitations=%v", input.Limitations)
	}
	// An opaque transform honestly breaks the trace: mask() reads a channel
	// (send sites are not inventoried), so the origin is UNKNOWN — the
	// recorded chain makes that UNKNOWN auditable instead of silent.
	if input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%s want UNKNOWN (opaque transform)", input.Result)
	}
}

// A platform fact FALSE is decided by the product snapshot, not code
// scope — negative verification VERIFIED and the verdict is
// NO_EXPLOIT_PATH_FOUND rather than an unresolved INCONCLUSIVE.
func TestE2EPlatformFactFalseVerified(t *testing.T) {
	repo := initRepoFrom(t, "extprod")
	dir := t.TempDir()
	other := "plan9"
	if runtime.GOOS == "plan9" {
		other = "haiku" // keep the mismatch impossible
	}
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-PLAT","kind":"PLATFORM_CONDITION","mandatory":true,
		 "description":"exploit requires a different OS",
		 "params":{"goos":"` + other + `"}}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/extprod","package":"example.com/extprod","function":"main","position":{"filename":"main.go","line":10}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": exactTestVuln(),
		}},
		VulnID:          "GO-TEST-1",
		Resolver:        stubResolver{},
		ManualRC:        []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:           mp,
		CaseDir:         filepath.Join(dir, "cases"),
		Govulncheck:     fakeGovulncheck{out: []byte(gv)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})
	plat := findClaimT(t, c.Claims, "C-PLAT")
	if plat.Result != domain.ClaimFalse {
		t.Fatalf("C-PLAT=%s want FALSE", plat.Result)
	}
	if plat.NegativeVerification == nil ||
		plat.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("NV=%+v want VERIFIED", plat.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

// A guard wrapped in a config-reading conditional does not unconditionally
// cover the sink (spec §19 configuration overrides): negative verification
// must downgrade to INSUFFICIENT_SCOPE and the verdict stays INCONCLUSIVE.
func TestE2EConfigGatedGuardStaysInconclusive(t *testing.T) {
	repo := initRepoFrom(t, "cfggateprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-VALID","kind":"VALIDATION","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/cfggateprod","package":"example.com/cfggateprod","function":"main","position":{"filename":"main.go","line":20}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:          "GO-TEST-1",
		Resolver:        stubResolver{},
		ManualRC:        []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:           mp,
		CaseDir:         filepath.Join(dir, "cases"),
		Govulncheck:     fakeGovulncheck{out: []byte(gv)},
		SnapshotOptions: declaredSnapshotOptions(),
		UseSource:       true,
	})
	// The guard is conditional on an external STRICT_MODE value, so the
	// analyzer cannot establish that it covers the sink. That is an
	// unsupported proof, not an admitted external fact: the case fails with
	// the verification cause instead of abstaining.
	valid := findClaimT(t, c.Claims, "C-VALID")
	if valid.NegativeVerification == nil ||
		valid.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("NV=%+v want INSUFFICIENT_SCOPE (guard is config-gated)", valid.NegativeVerification)
	}
	requireAssessmentFailed(t, c, domain.GapNegativeVerificationIncomplete)
}

// initRepoFiles git-inits a temp repo with the given files.
func initRepoFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return initGit(t, dir)
}

// unknownReachModel leaves C-REACH UNKNOWN without a source index, so the
// pipeline reaches GAP_ANALYSIS — the state under test here.
func unknownReachModel(t *testing.T, dir string) string {
	t.Helper()
	mp := filepath.Join(dir, "model.json")
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}}
	]}`
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	return mp
}

// gapCaseDeps fills the shared engine deps for a case that lands in
// GAP_ANALYSIS with an unresolved C-REACH claim.
func gapCaseDeps(t *testing.T, repo, dir string) engineDeps {
	t.Helper()
	return engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:    unknownReachModel(t, dir),
		CaseDir:  filepath.Join(dir, "cases"),
	}
}

func evidenceKinds(c *domain.AnalysisCase) map[domain.EvidenceKind]bool {
	out := map[domain.EvidenceKind]bool{}
	for _, e := range c.EvidenceGraph.Evidence {
		out[e.Kind] = true
	}
	return out
}

func hasLimitation(c *domain.AnalysisCase, substr string) bool {
	for _, l := range c.EvidenceGraph.Limitations {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// B2: with --allow-exec the gap loop runs `go build`/`go test` once as
// case-level evidence — BUILD/TEST records land in the graph, the runs in
// tool_executions, a hypothesis in the case and a section in report.md.
func TestE2EBuildTestEvidence(t *testing.T) {
	repo := initRepoFiles(t, map[string]string{
		"go.mod":       "module example.com/product\n\ngo 1.23\n",
		"main.go":      "package main\n\nfunc main() {}\n",
		"main_test.go": "package main\n\nimport \"testing\"\n\nfunc TestCompiles(t *testing.T) {}\n",
	})
	dir := t.TempDir()
	d := gapCaseDeps(t, repo, dir)
	d.AllowExec = true
	c := runEngine(t, d)

	// Build/test evidence is recorded, but the unresolved C-REACH failed the
	// analysis: the terminal state is FAILED, never a bare INCONCLUSIVE.
	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
	}
	requireAssessmentFailed(t, c, domain.GapReachabilityProofIncomplete)
	kinds := evidenceKinds(c)
	if !kinds[domain.EvidenceBuild] || !kinds[domain.EvidenceTest] {
		t.Fatalf("BUILD/TEST evidence missing: %v", kinds)
	}
	var ranBuild, ranTest bool
	for _, tx := range c.EvidenceGraph.ToolExecutions {
		if tx.Tool != "go" || len(tx.Args) < 2 || tx.Args[len(tx.Args)-1] != "./..." {
			continue
		}
		ranBuild = ranBuild || tx.Args[0] == "build"
		ranTest = ranTest || tx.Args[0] == "test"
	}
	if !ranBuild || !ranTest {
		t.Fatalf("go build/test executions not audited: %+v", c.EvidenceGraph.ToolExecutions)
	}
	// go build writes main-package executables into the work dir by
	// default — the action must not mutate the analyzed repository.
	if _, err := os.Stat(filepath.Join(repo, "product")); err == nil {
		t.Fatal("go build polluted the analyzed repo with an executable")
	}
	var hyp *domain.Hypothesis
	for i := range c.Hypotheses {
		if len(c.Hypotheses[i].ExpectedEvidence) == 2 &&
			c.Hypotheses[i].ExpectedEvidence[0] == domain.EvidenceBuild {
			hyp = &c.Hypotheses[i]
		}
	}
	if hyp == nil || len(hyp.EvidenceIDs) != 2 {
		t.Fatalf("build/test hypothesis missing: %+v", c.Hypotheses)
	}
	md, err := os.ReadFile(filepath.Join(d.CaseDir, string(c.ID), "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "Build & Test") {
		t.Fatal("report.md lacks the Build & test section")
	}
}

// Without --allow-exec the actions must not run: an honest limitation
// records the skip and no BUILD/TEST evidence exists.
func TestE2EBuildTestSkippedWithoutExec(t *testing.T) {
	repo := initRepoFiles(t, map[string]string{
		"go.mod":  "module example.com/product\n\ngo 1.23\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})
	dir := t.TempDir()
	d := gapCaseDeps(t, repo, dir)
	c := runEngine(t, d)

	kinds := evidenceKinds(c)
	if kinds[domain.EvidenceBuild] || kinds[domain.EvidenceTest] {
		t.Fatalf("exec evidence recorded without --allow-exec: %v", kinds)
	}
	if !hasLimitation(c, "requires --allow-exec") {
		t.Fatalf("skip limitation missing: %v", c.EvidenceGraph.Limitations)
	}
}

// A non-compiling snapshot is evidence, not a silent failure: BUILD
// records the failure and a limitation warns that static evidence may be
// unreliable.
func TestE2EBuildFailureLimitation(t *testing.T) {
	repo := initRepoFiles(t, map[string]string{
		"go.mod":  "module example.com/product\n\ngo 1.23\n",
		"main.go": "package main\n\nfunc main( {\n",
	})
	dir := t.TempDir()
	d := gapCaseDeps(t, repo, dir)
	d.AllowExec = true
	c := runEngine(t, d)

	var build *domain.Evidence
	for i, e := range c.EvidenceGraph.Evidence {
		if e.Kind == domain.EvidenceBuild {
			build = &c.EvidenceGraph.Evidence[i]
		}
	}
	if build == nil || !strings.Contains(build.Content, "FAILED") {
		t.Fatalf("BUILD evidence missing or not failed: %+v", build)
	}
	if !hasLimitation(c, "does not compile") {
		t.Fatalf("compile limitation missing: %v", c.EvidenceGraph.Limitations)
	}
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v want none: the build failure leaves conditions unresolved", c.Verdict)
	}
	if !hasAnalysisGap(c, domain.GapReachabilityProofIncomplete) {
		t.Fatalf("missing reachability cause: %+v", c.AnalysisGaps)
	}
}

// Backlog B3: provenance inside the dependency. readRecord is unexported
// — product code cannot call it — but its argument is the peer-fed wire
// reader. The dep-internal trace must resolve EXTERNAL_UNTRUSTED through
// c.r <- bufio.NewReader(conn) <- net.Dial, and the claim must carry the
// traced explanation, not the unexported+peer heuristic.
func TestE2EDepInternalPeerInput(t *testing.T) {
	repo := initRepoFrom(t, "wireprod")
	dir := t.TempDir()
	model := `{"impact":"peer bytes reach dep-internal parser","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "description":"readRecord reachable",
		 "subject":{"package":"example.com/dep/vuln","symbol":"readRecord"}},
		{"id":"C-PEER-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "description":"peer bytes drive the dep-internal parser",
		 "subject":{"package":"example.com/dep/vuln","symbol":"readRecord"},
		 "params":{"input_source":"peer"}}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-WIRE": {ID: "GO-TEST-WIRE", Module: "example.com/dep",
				AffectedSymbols: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "readRecord"}}},
		}},
		VulnID:    "GO-TEST-WIRE",
		Resolver:  stubResolver{},
		ManualRC:  []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "readRecord", Role: domain.RootCauseSink}},
		Model:     mp,
		CaseDir:   filepath.Join(dir, "cases"),
		UseSource: true,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	var depFlow *domain.DataFlow
	for i, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID == "C-PEER-INPUT" {
			depFlow = &c.EvidenceGraph.DataFlows[i]
		}
	}
	if depFlow == nil {
		t.Fatal("no data flow recorded for C-PEER-INPUT")
	}
	if depFlow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("dep-internal origin=%s want EXTERNAL_UNTRUSTED (%s)", depFlow.Origin, depFlow.Summary)
	}
	if !strings.Contains(depFlow.Sink.File, "dep") {
		t.Fatalf("dep flow sink=%s — expected dependency file", depFlow.Sink.File)
	}
	claim := findClaimT(t, c.Claims, "C-PEER-INPUT")
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("C-PEER-INPUT=%s want TRUE (%s)", claim.Result, claim.Explanation)
	}
	if strings.Contains(claim.Explanation, "unexported transport internals") {
		t.Fatalf("claim used the heuristic, not the trace: %s", claim.Explanation)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// The traced dep-internal constant cannot close the module's peer-fed
// ingress cone, and the known advisory symbol is not a complete sink set.
func TestE2EDepInternalConstantWithOpenIngress(t *testing.T) {
	repo := initRepoFrom(t, "wireprod")
	dir := t.TempDir()
	model := `{"impact":"peer bytes reach dep-internal parser","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "description":"parseConstant reachable",
		 "subject":{"package":"example.com/dep/vuln","symbol":"parseConstant"}},
		{"id":"C-PEER-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "description":"peer bytes drive the dep-internal parser",
		 "subject":{"package":"example.com/dep/vuln","symbol":"parseConstant"},
		 "params":{"input_source":"peer"}}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-CONST": {ID: "GO-TEST-CONST", Module: "example.com/dep",
				AffectedSymbols: []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "parseConstant"}}},
		}},
		VulnID:    "GO-TEST-CONST",
		Resolver:  stubResolver{},
		ManualRC:  []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "parseConstant", Role: domain.RootCauseSink}},
		Model:     mp,
		CaseDir:   filepath.Join(dir, "cases"),
		UseSource: true,
	})

	if c.Workflow.State != domain.StateFailed {
		t.Fatalf("state=%s reason=%s, want FAILED", c.Workflow.State, c.Workflow.Reason)
	}
	claim := findClaimT(t, c.Claims, "C-PEER-INPUT")
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("C-PEER-INPUT=%s want UNKNOWN (%s)", claim.Result, claim.Explanation)
	}
	if claim.NegativeVerification != nil &&
		claim.NegativeVerification.Status == domain.NegativeVerified {
		t.Fatalf("negative verification=%+v despite unclosed ingress", claim.NegativeVerification)
	}
	requireAssessmentFailed(t, c, domain.GapInputTraceIncomplete)
}

// When two affected-module entries are both linked into the product,
// narrowing must union their symbol/package sets — picking only the
// first entry would drop the second module's vulnerable path from
// downstream analysis.
type multiResolver struct{ res domain.AffectedResult }

func (m multiResolver) Resolve(context.Context, domain.Vulnerability, domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	return m.res, nil, nil
}

// evidenceResolver returns one resolver fact next to the affected result, so a
// scope-refusal case can prove the component evidence was recorded rather than
// dropped with the refused conclusion.
type evidenceResolver struct {
	res domain.AffectedResult
	ev  domain.Evidence
}

func (r evidenceResolver) Resolve(context.Context, domain.Vulnerability, domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	return r.res, []domain.Evidence{r.ev}, nil
}

func TestCheckAffectedUnionsSelectedModules(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep"
	c.Vulnerability.AffectedModules = []domain.AffectedModule{
		{
			Module:           "example.com/dep",
			AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			AffectedSymbols:  []domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Sink"}},
		},
		{
			Module:           "example.com/other",
			AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
			AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			AffectedSymbols:  []domain.SymbolRef{{Package: "example.com/other/vuln", Symbol: "OtherSink"}},
		},
	}
	res := domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
		SelectedModule:  "example.com/dep",
		SelectedModules: []string{"example.com/dep", "example.com/other"},
	}
	tr, err := states.CheckAffected{Resolver: multiResolver{res: res}}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateResolveRootCause {
		t.Fatalf("transition=%+v", tr)
	}
	found := map[string]bool{}
	for _, s := range c.Vulnerability.AffectedSymbols {
		found[s.Package+"."+s.Symbol] = true
	}
	if !found["example.com/dep/vuln.Sink"] || !found["example.com/other/vuln.OtherSink"] {
		t.Fatalf("symbols must union across selected modules: %+v", c.Vulnerability.AffectedSymbols)
	}
	if len(c.Vulnerability.AffectedPackages) != 2 {
		t.Fatalf("packages=%+v", c.Vulnerability.AffectedPackages)
	}
}

type failingBuilder struct{}

func (failingBuilder) Build(context.Context, *domain.AnalysisCase, domain.Vulnerability, *domain.RootCauseModel) (*domain.ExploitModel, []string) {
	return nil, []string{"strict-llm: builder failed"}
}

func TestBuildExploitModelStrictLLMFailsFast(t *testing.T) {
	c := &domain.AnalysisCase{
		StrictLLM: true,
		RootCause: &domain.RootCauseModel{Status: domain.RootCauseResolved},
	}
	tr, err := states.BuildExploitModel{Builder: failingBuilder{}}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateBuildReport {
		t.Fatalf("want transition to BUILD_REPORT (fail-fast still writes the report), got %+v", tr)
	}
	if !strings.Contains(tr.Reason, "strict-llm:") {
		t.Fatalf("want reason with strict-llm:, got %s", tr.Reason)
	}
	if c.Verdict != nil {
		t.Fatalf("strict-LLM failure published a verdict: %+v", c.Verdict)
	}
	if !hasAnalysisGap(c, domain.GapMeasurementNotCompleted) {
		t.Fatalf("strict-LLM failure lacks its typed cause: %+v", c.AnalysisGaps)
	}
}

type fakeCVECompleter struct{}

func (fakeCVECompleter) Complete(ctx context.Context, role llm.ModelRole, system, user string) (string, string, error) {
	if strings.Contains(user, "Review whether") {
		return `{"passed":true,"findings":[]}`, "stop", nil
	}
	if strings.Contains(user, "verification strategy plan") {
		return `{"selected_strategy":"LOCUS_ABSENT","obligations":[]}`, "stop", nil
	}
	return `{"action":"final","proposal":{"id":"P-1","confidence":"HIGH","mechanisms":[{"id":"M-1","summary":"xDS panic","faulting_sites":["pkg.Fault"],"auxiliary_sites":["pkg.Aux"]}]}}`, "stop", nil
}

// Reviewer agreement is recorded, not authority: a passed verified-profile
// review must not mint expert non-locus exclusions or otherwise shrink L.
func TestVerifiedResearchNeverAutoAcceptsLocus(t *testing.T) {
	c := &domain.AnalysisCase{
		CVEAnalysisProfile: domain.ProfileVerified,
		Vulnerability: domain.Vulnerability{
			ID: "GO-2026-6443",
		},
	}
	err := states.ActResearchCVE(context.Background(), c, nil, fakeCVECompleter{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.SemanticReview == nil || !c.SemanticReview.Passed {
		t.Errorf("expected SemanticReview to be present and passed")
	}
	if len(c.NonLocusBasis) != 0 {
		t.Fatalf("verified research must not mint expert non-locus exclusions: %+v", c.NonLocusBasis)
	}
}

// The agent's fallback may add evidence and nominate a result, but the
// authoritative TRUE must come from the deterministic chain re-running over
// that evidence; the nomination survives as audit material.
type agentEvidenceFallback struct{ added bool }

func (f *agentEvidenceFallback) CanEvaluate(domain.Condition) bool { return true }

func (f *agentEvidenceFallback) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	f.added = true
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID: "EV-AGENT-FACT", Kind: domain.EvidenceSourceSnippet, Quality: domain.QualityDeterministic,
		Source: "model-requested tool", Content: "call site observed by the agent's tool",
	})
	return domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Proposal:    domain.ClaimTrue,
		EvidenceIDs: []domain.EvidenceID{"EV-AGENT-FACT"},
		Limitations: []string{"llm proposed TRUE; recorded as a proposal"},
	}
}

// evidenceDependentEvaluator establishes TRUE only when the agent's tool has
// actually added the fact the condition needs.
type evidenceDependentEvaluator struct{}

func (evidenceDependentEvaluator) CanEvaluate(cond domain.Condition) bool {
	return cond.ID == "C-RUNTIME"
}

func (evidenceDependentEvaluator) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
	}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.ID == "EV-AGENT-FACT" {
			claim.Result = domain.ClaimTrue
			claim.Producer = "deterministic-reevaluation"
			claim.EvidenceIDs = []domain.EvidenceID{e.ID}
			return claim
		}
	}
	return claim
}

func TestGapReevaluatesAfterAgentEvidence(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{
			{ID: "C-RUNTIME", Kind: domain.ConditionRuntime, Mandatory: true},
		}},
		Claims: []domain.Claim{{ID: "CL-C-RUNTIME", ConditionID: "C-RUNTIME", Result: domain.ClaimUnknown}},
	}
	fallback := &agentEvidenceFallback{}
	tr, err := (states.GapAnalysis{
		Source:     &goanalysis.Index{Dir: t.TempDir()},
		Evaluators: []evaluator.ConditionEvaluator{evidenceDependentEvaluator{}},
		Fallback:   fallback,
	}).Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !fallback.added {
		t.Fatal("the agent fallback did not run")
	}
	cl := c.Claims[0]
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("deterministic reevaluation must establish TRUE from the agent's evidence: %+v", cl)
	}
	if cl.Proposal != domain.ClaimTrue {
		t.Fatalf("the model nomination must survive the authoritative result: %+v", cl)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("all mandatory conditions are satisfied, want REVIEW, got %+v", tr)
	}
}

const postReachModel = `{"impact":"config trigger","mandatory_conditions":[
	{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
	 "subject":{"package":"example.com/postreachdep/transformer","symbol":"QueryAll"}},
	{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
	 "subject":{"package":"example.com/postreachdep/transformer","symbol":"QueryAll"},"arg_index":1}
]}`

func postReachAssumptionInput(reviewDate string) *domain.DeclaredAssumptionsInput {
	a := domain.DeclaredAssumption{
		ID:         "ASM-CONFIG-TRUST",
		Kind:       domain.AssumptionConfigTrust,
		Statement:  "administrator-managed configuration is outside the attacker model",
		Scope:      domain.AssumptionScopeProduct,
		Authority:  "platform-security",
		Owner:      "platform-security",
		SourceRef:  "policy:threat-model",
		ValidFrom:  "2020-01-01",
		ReviewDate: reviewDate,
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	return &domain.DeclaredAssumptionsInput{
		Path:        "local:assumptions.json",
		Schema:      domain.DeclaredAssumptionsSchema,
		Assumptions: []domain.DeclaredAssumption{a},
	}
}

func runPostReachEngine(t *testing.T, assumptions *domain.DeclaredAssumptionsInput) *domain.AnalysisCase {
	t.Helper()
	repo := initRepoFrom(t, "configoriginprod")
	dir := t.TempDir()
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(postReachModel), 0o644); err != nil {
		t.Fatal(err)
	}
	return runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-CONFIG": {
				ID:     "GO-TEST-CONFIG",
				Module: "example.com/postreachdep",
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/postreachdep/transformer",
				}},
				AffectedSymbols: []domain.SymbolRef{{
					Package: "example.com/postreachdep/transformer", Symbol: "QueryAll",
				}},
			},
		}},
		VulnID:   "GO-TEST-CONFIG",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/postreachdep/transformer", Symbol: "QueryAll", Role: domain.RootCauseSink,
		}},
		Model:           mp,
		CaseDir:         filepath.Join(dir, "cases"),
		UseSource:       true,
		SnapshotOptions: declaredSnapshotOptions(),
		Assumptions:     assumptions,
	})
}

// The collector persists the exact site/argument flows and an
// advisory-bound sink closure, but configuration origin alone cannot
// ground the falsifier: without the declared assumption the claim stays
// UNKNOWN.
func TestE2EPostReachConfigNeedsAssumption(t *testing.T) {
	c := runPostReachEngine(t, nil)
	claim := findClaimT(t, c.Claims, "C-INPUT")
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%s want UNKNOWN without config-trust assumption (%s)", claim.Result, claim.Explanation)
	}
	if claim.Falsifier != "" || len(claim.AssumptionIDs) != 0 {
		t.Fatalf("claim=%+v", claim)
	}
	if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNotAffected {
		t.Fatalf("config route produced NOT_AFFECTED: %+v", c.Verdict)
	}
}

// With an admissible config-trust assumption the exact-argument closure
// grounds the claim; the exact site/argument DataFlow is retained.
func TestE2EPostReachConfigClosesWithAssumption(t *testing.T) {
	c := runPostReachEngine(t, postReachAssumptionInput("2999-12-31"))
	claim := findClaimT(t, c.Claims, "C-INPUT")
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("C-INPUT=%s want FALSE (%s)", claim.Result, claim.Explanation)
	}
	if claim.Falsifier != domain.FalsifierTrustedInfrastructure ||
		claim.FalsifierBasis != domain.BasisConfigOrigin {
		t.Fatalf("falsifier=%s basis=%s", claim.Falsifier, claim.FalsifierBasis)
	}
	if len(claim.AssumptionIDs) != 1 || claim.AssumptionIDs[0] != "ASM-CONFIG-TRUST" {
		t.Fatalf("assumption ids=%v", claim.AssumptionIDs)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("negative verification=%+v", claim.NegativeVerification)
	}
	var exact bool
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID == "C-INPUT" && f.Arg == 1 &&
			f.Origin == domain.OriginConfiguration &&
			strings.HasSuffix(f.Sink.File, "main.go") && f.Sink.Function == "run" {
			exact = true
		}
	}
	if !exact {
		t.Fatalf("no exact config DataFlow at arg 1: %+v", c.EvidenceGraph.DataFlows)
	}
	cl := c.EvidenceGraph.SinkClosureFor("C-INPUT")
	if cl == nil || !cl.Complete || cl.Basis == "" {
		t.Fatalf("sink closure=%+v", cl)
	}
	if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNotAffected {
		t.Fatalf("config route produced NOT_AFFECTED: %+v", c.Verdict)
	}
}

// partialCVEScope is a CVE-wide request bound to one loaded record: component
// facts stay usable, but the requested identity can never close.
func partialCVEScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{RequestedID: "CVE-2023-44487", ResolvedID: "GO-TEST-1", Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly}
}

// projectedScope is an exact identity whose loaded document represented only
// its Go entry: the omitted Maven entry keeps the requested scope uncovered
// even though the scope claims COMPLETE coverage of an exact record.
func projectedScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1",
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentGoProjection,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID: "GO-TEST-1", DocumentDigest: "sha256:" + strings.Repeat("cd", 32),
			AffectedEntryCount: 2,
			Entries: []domain.RecordEntry{
				{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"},
				{Index: 1, Ecosystem: "Maven", Module: "io.grpc:grpc-netty"},
			},
			RepresentedRefs: []int{0},
			OmittedRefs:     []int{1},
		},
	}
}

// unbackedCompleteScope is the legacy persisted shape: COMPLETE coverage with
// no structural census. It no longer authorizes a negative closure.
func unbackedCompleteScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{RequestedID: "GO-TEST-1", ResolvedID: "GO-TEST-1", Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete}
}

func TestCheckAffectedPartialScopeContinues(t *testing.T) {
	for _, scope := range []struct {
		name  string
		scope *domain.AdvisoryScope
	}{
		{"cve-known-only", partialCVEScope()},
		{"exact-projected", projectedScope()},
		{"exact-complete-without-census", unbackedCompleteScope()},
	} {
		for _, extraModule := range []bool{false, true} {
			t.Run(scope.name+fmt.Sprintf("/extra-module=%t", extraModule), func(t *testing.T) {
				c := &domain.AnalysisCase{Vulnerability: domain.Vulnerability{
					ID: "GO-TEST-1", Scope: scope.scope, Module: "golang.org/x/net",
					AffectedModules: []domain.AffectedModule{{Module: "golang.org/x/net", FixedVersions: []string{"v0.17.0"}}},
				}}
				c.Product.ReleaseModules = []domain.ReleaseModule{{Path: "golang.org/x/net", Version: "v0.17.0"}}
				if extraModule {
					c.Product.ReleaseModules = append(c.Product.ReleaseModules, domain.ReleaseModule{Path: "example.com/alternate", Version: "v1.0.0"})
				}
				res := domain.AffectedResult{
					Scope: scope.scope, ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse,
					ResolvedVersion: "v0.17.0", CheckedModules: []string{"golang.org/x/net"}, EvidenceIDs: []domain.EvidenceID{"EV-XNET"},
				}
				resolver := evidenceResolver{res: res, ev: domain.Evidence{
					ID: "EV-XNET", Kind: domain.EvidenceModuleGraph, Quality: domain.QualityDeterministic,
					Content: "golang.org/x/net@v0.17.0",
				}}
				tr, err := (states.CheckAffected{Resolver: resolver}).Run(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				if tr.Next != domain.StateResolveRootCause {
					t.Fatalf("refused scope transition = %+v", tr)
				}
				if c.Affected.ModulePresent != domain.ClaimTrue || c.Affected.VersionAffected != domain.ClaimFalse ||
					c.Affected.ResolvedVersion != "v0.17.0" || c.Affected.Scope != scope.scope {
					t.Fatalf("component facts changed: %+v", c.Affected)
				}
				if len(c.Affected.EvidenceIDs) != 1 || c.Affected.EvidenceIDs[0] != "EV-XNET" ||
					len(c.Affected.CheckedModules) != 1 || c.Affected.CheckedModules[0] != "golang.org/x/net" {
					t.Fatalf("evidence or checked modules changed: %+v", c.Affected)
				}
				limitation := strings.Join(c.Affected.Limitations, "; ")
				for _, want := range []string{"scope", scope.scope.RequestedID, "golang.org/x/net"} {
					if !strings.Contains(limitation, want) {
						t.Fatalf("limitation %q does not name %q", limitation, want)
					}
				}
				// The refusal is recorded on the case, not only on the
				// affected result, and the component evidence survives.
				graphLimitation := strings.Join(c.EvidenceGraph.Limitations, "; ")
				if !strings.Contains(graphLimitation, scope.scope.RequestedID) {
					t.Fatalf("case limitations do not record the refusal: %q", graphLimitation)
				}
				if c.EvidenceGraph.EvidenceByID("EV-XNET") == nil {
					t.Fatal("component evidence was not retained")
				}
				if len(c.Vulnerability.AffectedModules) != 1 || c.Vulnerability.AffectedModules[0].Module != "golang.org/x/net" {
					t.Fatalf("advisory entries changed: %+v", c.Vulnerability.AffectedModules)
				}
				if extraModule && (len(c.Product.ReleaseModules) != 2 || c.Product.ReleaseModules[1].Version != "v1.0.0") {
					t.Fatalf("uncovered module inherited version fact: %+v", c.Product.ReleaseModules)
				}
				got := evalBareVerdict(*c.Affected, domain.ExploitModel{}, nil)
				if got.Verdict != domain.VerdictInconclusive {
					t.Fatalf("refused scope final verdict = %+v", got)
				}
			})
		}
	}
}

func TestCheckAffectedExactEntryScopeNegativeCloses(t *testing.T) {
	scope := exactScope("GO-TEST-1")
	c := &domain.AnalysisCase{}
	res := domain.AffectedResult{Scope: scope, ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse, ResolvedVersion: "v0.17.0"}
	tr, err := (states.CheckAffected{Resolver: multiResolver{res: res}}).Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("exact-entry scope transition = %+v", tr)
	}
	got := evalBareVerdict(*c.Affected, domain.ExploitModel{}, nil)
	if got.Verdict != domain.VerdictNotAffected {
		t.Fatalf("exact-entry negative = %+v", got)
	}
}

func TestCheckAffectedImplementationScopePreserved(t *testing.T) {
	for _, original := range []struct {
		name  string
		scope *domain.AdvisoryScope
		want  domain.WorkflowState
	}{
		{"no scope", nil, domain.StateResolveRootCause},
		{"cve known-only", partialCVEScope(), domain.StateResolveRootCause},
		{"exact projected", projectedScope(), domain.StateResolveRootCause},
		{"exact complete without census", unbackedCompleteScope(), domain.StateResolveRootCause},
		{"exact full record", exactScope("GO-TEST-1"), domain.StateEvaluateVerdict},
	} {
		for _, callbackScope := range []*domain.AdvisoryScope{nil, exactScope("GO-TEST-1")} {
			t.Run(fmt.Sprintf("%s/callback-scope=%t", original.name, callbackScope != nil), func(t *testing.T) {
				var before *domain.AdvisoryScope
				if original.scope != nil {
					before = original.scope.Clone()
				}
				res := domain.AffectedResult{Scope: original.scope, ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimTrue}
				c := &domain.AnalysisCase{}
				h := states.CheckAffected{Resolver: multiResolver{res: res}, ImplementationAxis: func(_ context.Context, _ *domain.AnalysisCase, r domain.AffectedResult) affected.ImplementationAxisResult {
					if r.Scope != nil {
						r.Scope.Coverage = domain.CoverageComplete
					}
					r.Scope = callbackScope
					return affected.ImplementationAxisResult{Affected: r, Present: domain.ClaimFalse}
				}}
				tr, err := h.Run(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				if tr.Next != original.want || c.Affected.Scope != original.scope {
					t.Fatalf("callback changed scope authority: transition=%+v affected=%+v", tr, c.Affected)
				}
				if !reflect.DeepEqual(original.scope, before) {
					t.Fatalf("callback mutated the original scope: got %+v, want %+v", original.scope, before)
				}
			})
		}
	}
}

// TestCheckAffectedCallbackScopeIsolation: the implementation-axis callback
// receives a deep copy of the authoritative scope. Rewriting the record
// identity, the census entries, the represented refs or the omitted refs must
// not reach the original scope, change its closure decision, or alter the
// transition — scope stays the finding-level authority resolved from the
// advisory record.
func TestCheckAffectedCallbackScopeIsolation(t *testing.T) {
	mutations := map[string]func(*domain.AdvisoryScope){
		"coverage rewrite": func(s *domain.AdvisoryScope) { s.Coverage = domain.CoverageKnownOnly },
		"extent rewrite":   func(s *domain.AdvisoryScope) { s.RecordExtent = domain.RecordExtentGoProjection },
		"identity rewrite": func(s *domain.AdvisoryScope) { s.RecordInventory.AdvisoryID = "GO-OTHER-1" },
		"entries dropped":  func(s *domain.AdvisoryScope) { s.RecordInventory.Entries = nil },
		"entry identity rewrite": func(s *domain.AdvisoryScope) {
			s.RecordInventory.Entries[0].Module = "example.com/attacker"
		},
		"represented dropped": func(s *domain.AdvisoryScope) { s.RecordInventory.RepresentedRefs = nil },
		"represented appended": func(s *domain.AdvisoryScope) {
			s.RecordInventory.RepresentedRefs = append(s.RecordInventory.RepresentedRefs, 0)
		},
		"omitted added": func(s *domain.AdvisoryScope) { s.RecordInventory.OmittedRefs = []int{0} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			original := exactScope("GO-TEST-1")
			before := original.Clone()
			res := domain.AffectedResult{
				Scope: original, ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue,
				PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimTrue,
			}
			c := &domain.AnalysisCase{}
			h := states.CheckAffected{Resolver: multiResolver{res: res}, ImplementationAxis: func(_ context.Context, _ *domain.AnalysisCase, r domain.AffectedResult) affected.ImplementationAxisResult {
				mutate(r.Scope)
				return affected.ImplementationAxisResult{Affected: r, Present: domain.ClaimFalse}
			}}
			tr, err := h.Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if tr.Next != domain.StateEvaluateVerdict || c.Affected.Scope != original {
				t.Fatalf("callback mutation changed scope authority: transition=%+v scope=%+v", tr, c.Affected.Scope)
			}
			if !reflect.DeepEqual(original, before) {
				t.Fatalf("callback mutated the original scope: got %+v, want %+v", original, before)
			}
			if !original.AllowsNegativeClosure() {
				t.Fatalf("closure decision changed: %+v", original)
			}
		})
	}
}

func TestCheckAffectedImplementationScopePrerequisites(t *testing.T) {
	for _, unknownAxis := range []string{"package", "build"} {
		res := domain.AffectedResult{
			Scope:         exactScope("GO-TEST-1"),
			ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue,
			PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimTrue,
			VulnerableImplementationPresent: domain.ClaimFalse,
		}
		if unknownAxis == "package" {
			res.PackagePresent = domain.ClaimUnknown
		} else {
			res.BuildRelevant = domain.ClaimUnknown
		}
		tr, err := (states.CheckAffected{Resolver: multiResolver{res: res}}).Run(context.Background(), &domain.AnalysisCase{})
		if err != nil {
			t.Fatal(err)
		}
		if tr.Next != domain.StateResolveRootCause {
			t.Fatalf("implementation negative with %s unresolved closed: %+v", unknownAxis, tr)
		}
	}
}

// fixedSnapshotter returns one prepared snapshot for SnapshotProduct tests.
type fixedSnapshotter struct {
	snap domain.ProductSnapshot
	err  error
}

func (f fixedSnapshotter) Snapshot(context.Context, string, repository.SnapshotOptions) (domain.ProductSnapshot, error) {
	return f.snap, f.err
}

// SnapshotProduct binds the resolved product build into the case's source
// index before root-cause resolution can load it: a pre-load context is
// adopted, a caller-resolved scan snapshot is reused without re-probing, and
// a post-load mismatch fails the state instead of relabelling loaded ASTs.
func TestSnapshotBindsBeforeRootCause(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/bindcase\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap := domain.ProductSnapshot{
		Repository: dir, Commit: "abc123", GoVersion: "go version go1.25.0 linux/arm64",
		GoModDirective: "1.23", GOOS: "linux", GOARCH: "arm64",
		GoWorkFile: domain.GoWorkOff, GoFlags: "-mod=readonly",
		Target: &domain.ProductTarget{
			GOOS: "linux", GOARCH: "arm64",
			Source: domain.ProductTargetSourceOperatorDeclared, Scope: domain.ProductTargetScopeOperator,
		},
	}

	// A different pre-load context is replaced by the resolved snapshot.
	ix := &goanalysis.Index{Dir: dir, Build: domain.ProductSnapshot{GOOS: "windows", GOARCH: "386"}}
	c := &domain.AnalysisCase{ID: "bind-case"}
	tr, err := (states.SnapshotProduct{Repo: fixedSnapshotter{snap: snap}, Path: dir, Source: ix}).
		Run(context.Background(), c)
	if err != nil {
		t.Fatalf("snapshot state: %v", err)
	}
	if tr.Next != domain.StateResolveVulnerability {
		t.Fatalf("transition = %+v, want resolve vulnerability", tr)
	}
	if c.Product.GOOS != "linux" || c.Product.GOARCH != "arm64" || c.Product.Target == nil {
		t.Fatalf("case product not captured: %+v", c.Product)
	}
	bound, ok := ix.BoundBuildContext()
	if !ok {
		t.Fatal("index is not bound after SnapshotProduct")
	}
	if err := bound.Matches(domain.EffectiveBuildContext(snap)); err != nil {
		t.Fatalf("bound context does not match the resolved snapshot: %v", err)
	}
	if ix.Build.Repository != dir || ix.Build.Target == nil ||
		ix.Build.Target.Source != domain.ProductTargetSourceOperatorDeclared {
		t.Fatalf("index did not adopt the resolved snapshot: %+v", ix.Build)
	}

	// A caller-resolved scan snapshot is reused: no snapshotter is needed.
	reused := states.SnapshotProduct{Path: dir, Snapshot: &snap, Source: &goanalysis.Index{Dir: dir}}
	c2 := &domain.AnalysisCase{ID: "bind-case-2"}
	tr, err = reused.Run(context.Background(), c2)
	if err != nil || tr.Next != domain.StateResolveVulnerability {
		t.Fatalf("pre-resolved snapshot: transition=%+v err=%v", tr, err)
	}

	// A pre-resolved snapshot for another repository fails closed.
	otherRepo := snap
	otherRepo.Repository = filepath.Join(dir, "elsewhere")
	c3 := &domain.AnalysisCase{ID: "bind-case-3"}
	tr, err = (states.SnapshotProduct{Path: dir, Snapshot: &otherRepo}).
		Run(context.Background(), c3)
	if err != nil {
		t.Fatalf("identity mismatch returned a workflow error: %v", err)
	}
	if tr.Next != domain.StateFailed || !strings.Contains(tr.Reason, "does not identify") {
		t.Fatalf("identity mismatch transition = %+v", tr)
	}

	// A loaded index is never relabelled: the state fails closed.
	live := &goanalysis.Index{Dir: dir}
	if err := live.Loaded(context.Background()); err != nil {
		t.Fatalf("load live index: %v", err)
	}
	before := live.Build
	c4 := &domain.AnalysisCase{ID: "bind-case-4"}
	tr, err = (states.SnapshotProduct{Repo: fixedSnapshotter{snap: snap}, Path: dir, Source: live}).
		Run(context.Background(), c4)
	if err != nil {
		t.Fatalf("post-load bind returned a workflow error: %v", err)
	}
	if tr.Next != domain.StateFailed || !strings.Contains(tr.Reason, "binding failed") {
		t.Fatalf("post-load mismatch transition = %+v", tr)
	}
	if !reflect.DeepEqual(live.Build, before) {
		t.Fatalf("failed bind mutated the loaded index: %+v -> %+v", before, live.Build)
	}

	// A plain binary whose settings did not yield a typed target records a
	// target-only limitation; the measured release toolchain is untouched
	// (no release-channel failure is fabricated).
	exe, exeErr := os.Executable()
	if exeErr != nil {
		t.Skipf("test binary unavailable: %v", exeErr)
	}
	gapSnap := snap
	gapSnap.BinaryPath = exe
	gapSnap.ReleaseGoVersion = "go1.25.0-measured"
	c5 := &domain.AnalysisCase{ID: "bind-case-5"}
	tr, err = (states.SnapshotProduct{
		Repo: fixedSnapshotter{snap: gapSnap}, Path: dir,
		Source: &goanalysis.Index{Dir: dir},
	}).Run(context.Background(), c5)
	if err != nil || tr.Next != domain.StateResolveVulnerability {
		t.Fatalf("binary target-gap state: transition=%+v err=%v", tr, err)
	}
	gapRecorded := false
	for _, lim := range c5.EvidenceGraph.Limitations {
		if strings.Contains(lim, "build-target extraction gap") {
			gapRecorded = true
		}
	}
	if !gapRecorded {
		t.Fatalf("binary target gap not recorded separately: %v", c5.EvidenceGraph.Limitations)
	}
	if c5.Product.ReleaseGoVersion != "go1.25.0-measured" {
		t.Fatalf("target gap invalidated the measured toolchain: %q", c5.Product.ReleaseGoVersion)
	}
	if c5.Product.ReleaseEvidence != nil &&
		len(c5.Product.ReleaseEvidence.RequiredChannelFailures) > 0 {
		t.Fatalf("target gap fabricated a release-channel failure: %v",
			c5.Product.ReleaseEvidence.RequiredChannelFailures)
	}
}

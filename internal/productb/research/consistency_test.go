package research

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// writeTree builds a snapshot dir from a name→content map.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// testAres is the advisory resolution shape used across the consistency
// tests: one Go affected entry for example.com/dep, [0, 1.2.4), fixed 1.2.4.
func testAres() advisoryResult {
	am := pbdomain.AffectedModule{
		Module:           "example.com/dep",
		AffectedVersions: []pbdomain.VersionRange{{Introduced: "0", Fixed: "1.2.4"}},
		FixedVersions:    []string{"1.2.4"},
	}
	doc := AdvisoryDocument{Role: "primary", ID: "GO-2024-3333", SHA256: "aa", Path: "advisory/GO-2024-3333.json"}
	return advisoryResult{
		info:       AdvisoryInfo{Status: "resolved", ID: doc.ID},
		affected:   []goAffectedRef{{am: am, doc: doc}},
		primaryDoc: doc,
	}
}

// consistencyFixture wires a minimal report for assessConsistency:
// a snapshot dir, an optional parsed answer.
func consistencyFixture(snapDir, category, reasoning string) (*Report, advisoryResult) {
	r := &Report{RunID: "t-run", Answer: AnswerInfo{AttemptID: "t-run"}}
	r.Snapshot.Path = snapDir
	r.Snapshot.ContentHash = "abc123"
	if category != "" {
		r.Answer = AnswerInfo{Category: category, Parsed: true, Reasoning: reasoning}
	}
	return r, testAres()
}

func entryByModule(cr ConsistencyReport, mod string) *ConsistencyEntry {
	for i := range cr.Entries {
		if cr.Entries[i].Module == mod {
			return &cr.Entries[i]
		}
	}
	return nil
}

func findingsOf(cr ConsistencyReport, kind string) []ConsistencyFinding {
	var out []ConsistencyFinding
	for _, f := range cr.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestConsistency_PresentInRange(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
	})
	r, vuln := consistencyFixture(snap, "", "")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	e := entryByModule(cr, "example.com/dep")
	if e == nil {
		t.Fatal("no consistency entry for example.com/dep")
	}
	if e.Presence != "present" || e.RangeStatus != "in_range" || e.ResolvedVersion != "v1.2.3" {
		t.Fatalf("entry = %+v", e)
	}
	if !strings.Contains(e.Evidence, "go.mod") {
		t.Fatalf("evidence must name the fact source: %q", e.Evidence)
	}
	if len(cr.Findings) != 0 {
		t.Fatalf("no answer parsed → no findings expected: %+v", cr.Findings)
	}
}

func TestConsistency_OutOfRange(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.4\n",
	})
	r, vuln := consistencyFixture(snap, "", "")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	e := entryByModule(cr, "example.com/dep")
	if e.Presence != "present" || e.RangeStatus != "out_of_range" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestConsistency_AbsentFromGraphIsNotProof(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n",
		"go.sum": "example.com/unrelated v9.9.9 h1:x=\n",
	})
	r, vuln := consistencyFixture(snap, "", "")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	e := entryByModule(cr, "example.com/dep")
	if e.Presence != "absent_from_graph" {
		t.Fatalf("entry = %+v", e)
	}
	if !strings.Contains(e.Statement, "not proof that no exploitation path exists") {
		t.Fatalf("absent entry must state absence is not proof: %q", e.Statement)
	}
	if !strings.Contains(cr.Caveat, "is not proof that no exploitation path exists") {
		t.Fatalf("caveat missing the absence rule: %q", cr.Caveat)
	}
	// No finding may assert absence of exploitation paths.
	for _, f := range cr.Findings {
		if strings.Contains(strings.ToLower(f.Statement), "no exploitation path exists") &&
			!strings.Contains(f.Statement, "not proof") {
			t.Fatalf("finding asserts absence as proof: %q", f.Statement)
		}
	}
}

func TestConsistency_UnknownWithoutGraph(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"main.go": "package main\n",
	})
	r, vuln := consistencyFixture(snap, "", "")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	e := entryByModule(cr, "example.com/dep")
	if e.Presence != "unknown" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestConsistency_VendorWinsOverRequire(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod":             "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.4\n",
		"vendor/modules.txt": "# example.com/dep v1.0.0\n## explicit; go 1.22\nexample.com/dep\n",
	})
	r, vuln := consistencyFixture(snap, "", "")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	e := entryByModule(cr, "example.com/dep")
	if e.ResolvedVersion != "v1.0.0" || !strings.Contains(e.Evidence, "vendor") {
		t.Fatalf("vendored version must win: %+v", e)
	}
	if e.RangeStatus != "in_range" {
		t.Fatalf("vendored v1.0.0 must be in range: %+v", e)
	}
}

func TestConsistency_StdlibUsesToolchain(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n",
	})
	r, _ := consistencyFixture(snap, "", "")
	doc := AdvisoryDocument{Role: "primary", ID: "GO-TEST"}
	ares := advisoryResult{
		info: AdvisoryInfo{Status: "resolved", ID: "GO-TEST"},
		affected: []goAffectedRef{{am: pbdomain.AffectedModule{
			Module:           "stdlib",
			AffectedVersions: []pbdomain.VersionRange{{Introduced: "0", Fixed: "1.22.5"}},
			FixedVersions:    []string{"1.22.5"},
		}, doc: doc}},
		primaryDoc: doc,
	}
	r.Snapshot.Module.GoModPresent = true
	r.Snapshot.Module.GoDirective = "1.22"
	cr := assessConsistency(Options{SnapshotDir: snap}, r, ares)

	e := entryByModule(cr, "stdlib")
	if e == nil || e.Presence != "present" || e.RangeStatus != "in_range" {
		t.Fatalf("stdlib entry = %+v", e)
	}
	if !strings.Contains(e.Evidence, "go directive") {
		t.Fatalf("stdlib evidence must name the toolchain source: %q", e.Evidence)
	}
}

func TestConsistency_AbsenceTensionOnlyForCodeNotPresent(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
	})

	// code_not_present + module present in range → category_absence_tension.
	r, vuln := consistencyFixture(snap, "code_not_present", "example.com/dep is not part of this product.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)
	fs := findingsOf(cr, "category_absence_tension")
	if len(fs) != 1 {
		t.Fatalf("want 1 category_absence_tension, got %+v", cr.Findings)
	}
	for _, want := range []string{"module present", "different scope", "not a refutation"} {
		if !strings.Contains(fs[0].Statement, want) {
			t.Fatalf("tension statement must carry %q: %s", want, fs[0].Statement)
		}
	}

	// code_not_reachable with the same facts → NEVER a tension: presence
	// says nothing about reachability of the vulnerable operation.
	for _, cat := range []string{"code_not_reachable", "requires_configuration", "mitigating_control_protected"} {
		r2, v2 := consistencyFixture(snap, cat, "the sink is unreachable in this product.")
		cr2 := assessConsistency(Options{SnapshotDir: snap}, r2, v2)
		if fs := findingsOf(cr2, "category_absence_tension"); len(fs) != 0 {
			t.Fatalf("category %s must not produce absence tension: %+v", cat, fs)
		}
		for _, f := range cr2.Findings {
			if strings.Contains(strings.ToLower(f.Statement), "not supported by the host facts") {
				t.Fatalf("category %s: presence must not refute the category: %q", cat, f.Statement)
			}
		}
	}
}

// A vulnerable answer beside an out-of-range module is shown as version
// facts, not converted into a contradiction — the category stays the
// agent's own, unsubstituted.
func TestConsistency_VulnerableOutOfRangeStaysFact(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.5.0\n",
	})
	r, vuln := consistencyFixture(snap, "vulnerable", "The product is exploitable.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	e := entryByModule(cr, "example.com/dep")
	if e.Presence != "present" || e.RangeStatus != "out_of_range" {
		t.Fatalf("entry = %+v", e)
	}
	for _, f := range cr.Findings {
		if f.Kind == "contradiction" || f.Kind == "category_absence_tension" {
			t.Fatalf("vulnerable + out_of_range must not be flagged: %+v", f)
		}
	}
	if r.Answer.Category != "vulnerable" {
		t.Fatalf("category must stay verbatim: %q", r.Answer.Category)
	}
}

func TestConsistency_CoverageIncomplete(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire (\n\texample.com/dep v1.2.3\n\tgoogle.golang.org/grpc v1.55.0\n)\n",
	})
	r, vuln := consistencyFixture(snap, "vulnerable",
		"Only example.com/dep is affected here; google.golang.org/grpc is not used.")
	vuln.affected = append(vuln.affected, goAffectedRef{am: pbdomain.AffectedModule{
		Module:           "google.golang.org/grpc",
		AffectedVersions: []pbdomain.VersionRange{{Introduced: "0", Fixed: "1.55.1"}},
	}, doc: vuln.primaryDoc})
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	// grpc IS named in the reasoning, so no unnamed-entry finding; dep too.
	// Now drop grpc from the reasoning entirely.
	r.Answer.Reasoning = "example.com/dep is the vulnerable component."
	cr = assessConsistency(Options{SnapshotDir: snap}, r, vuln)
	fs := findingsOf(cr, "coverage_incomplete")
	if len(fs) == 0 {
		t.Fatal("advisory entry unnamed by the answer must produce coverage_incomplete")
	}
	if !strings.Contains(fs[0].Statement, "google.golang.org/grpc") {
		t.Fatalf("coverage finding must name the unassessed entry: %q", fs[0].Statement)
	}
}

func TestConsistency_CoverageExtraModule(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire (\n\texample.com/dep v1.2.3\n\texample.com/other v1.9.9\n)\n",
	})
	r, vuln := consistencyFixture(snap, "code_not_reachable",
		"example.com/dep is unreachable and example.com/other wraps the sink.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	var extra bool
	for _, f := range findingsOf(cr, "coverage_incomplete") {
		if strings.Contains(f.Statement, "example.com/other") {
			extra = true
		}
	}
	if !extra {
		t.Fatalf("answer naming a non-advisory graph module must be surfaced: %+v", cr.Findings)
	}
}

func TestConsistency_VersionMismatch(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
	})
	r, vuln := consistencyFixture(snap, "code_not_present",
		"The bug was fixed in v0.18.0 upstream, and this tree carries v1.0.0.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)

	fs := findingsOf(cr, "version_mismatch")
	if len(fs) != 1 {
		t.Fatalf("want 1 version_mismatch, got %+v", cr.Findings)
	}
	if !strings.Contains(fs[0].Statement, "v0.18.0") || !strings.Contains(fs[0].Statement, "1.2.4") {
		t.Fatalf("mismatch must show claimed vs declared: %q", fs[0].Statement)
	}
}

func TestConsistency_NoMismatchWhenClaimedMatches(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.4\n",
	})
	r, vuln := consistencyFixture(snap, "code_not_present",
		"The bug was fixed in v1.2.4 upstream.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)
	if fs := findingsOf(cr, "version_mismatch"); len(fs) != 0 {
		t.Fatalf("matching fix claim must not produce a mismatch: %+v", fs)
	}
}

func TestConsistency_NotAssessedWithoutAdvisory(t *testing.T) {
	r := &Report{RunID: "t"}
	cr := assessConsistency(Options{SnapshotDir: t.TempDir()}, r, advisoryResult{})
	if cr.State != "not_assessed" || cr.Reason == "" {
		t.Fatalf("state = %+v", cr)
	}
}

func TestConsistency_EvidenceBoundToAttempt(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
	})
	r, vuln := consistencyFixture(snap, "requires_configuration", "x")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)
	r.Consistency = cr
	r.Snapshot.ContentHash = "deadbeef"
	bindEvidence(r)
	for _, e := range r.Consistency.Entries {
		if e.Attempt != "t-run" || e.SnapshotHash != "deadbeef" {
			t.Fatalf("entry not bound to attempt/hash: %+v", e)
		}
	}
	for _, f := range r.Consistency.Findings {
		if f.Attempt != "t-run" || f.SnapshotHash != "deadbeef" {
			t.Fatalf("finding not bound to attempt/hash: %+v", f)
		}
	}
}

func TestExtractionStates(t *testing.T) {
	snap := writeTree(t, map[string]string{"main.go": "package main\n"})

	// Parsed answer with no assumption/unknown sentences → not_established.
	out := t.TempDir()
	raw := `{"category":"vulnerable","reasoning":"example.com/dep renders the sink reachable."}`
	if err := os.WriteFile(filepath.Join(out, "raw_agent_output.txt"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Report{Analysis: Analysis{
		Assumptions: ExtractionList{State: "not_assessed", Items: []string{}},
		Unknowns:    ExtractionList{State: "not_assessed", Items: []string{}},
	}}
	analyzeAnswer(Options{SnapshotDir: snap}, r, out)
	if r.Analysis.Assumptions.State != "not_established" || r.Analysis.Unknowns.State != "not_established" {
		t.Fatalf("parsed-but-empty must be not_established: %+v / %+v",
			r.Analysis.Assumptions, r.Analysis.Unknowns)
	}

	// Unparseable answer → not_assessed.
	out2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(out2, "raw_agent_output.txt"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	r2 := &Report{Analysis: Analysis{
		Assumptions: ExtractionList{State: "not_assessed", Items: []string{}},
		Unknowns:    ExtractionList{State: "not_assessed", Items: []string{}},
	}}
	analyzeAnswer(Options{SnapshotDir: snap}, r2, out2)
	if r2.Analysis.Assumptions.State != "not_assessed" || r2.Analysis.Unknowns.State != "not_assessed" {
		t.Fatalf("unparseable must stay not_assessed: %+v / %+v",
			r2.Analysis.Assumptions, r2.Analysis.Unknowns)
	}
}

// stubDocker writes a fake docker executable implementing the subcommands
// the launcher uses: create, start, cp, kill, rm.
func stubDocker(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "docker-stub.sh")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

const dockerStubOK = `#!/bin/sh
case "$1" in
  create) echo deadbeefcafe ;;
  start) exit 0 ;;
  cp) cat > "$3" <<'EOF'
AGENT_STDOUT_PAYLOAD
EOF
    ;;
  *) exit 0 ;;
esac
`

func TestRun_InvalidAnswerPartialReport(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := stubDocker(t, strings.Replace(dockerStubOK, "AGENT_STDOUT_PAYLOAD", "this is not json at all", 1))

	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		AllowAgent: true, DockerBin: stub,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Run.Status != "invalid_answer" {
		t.Fatalf("run status = %s", rep.Run.Status)
	}
	if rep.ResearchState != "incomplete" {
		t.Fatalf("research_state = %s", rep.ResearchState)
	}
	runDir := filepath.Join(out, "runs", rep.RunID)
	for _, name := range []string{"report.json", "report.md", "audit.json", "raw_agent_output.txt"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("%s missing — partial result must be kept: %v", name, err)
		}
	}
	if rep.Answer.RawPath != "raw_agent_output.txt" || rep.Answer.ParseError == "" {
		t.Fatalf("raw answer path / parse error not recorded: %+v", rep.Answer)
	}
	if rep.Analysis.Assumptions.State != "not_assessed" {
		t.Fatalf("assumptions state = %s", rep.Analysis.Assumptions.State)
	}
	// Host facts survive the failed answer.
	if len(rep.Analysis.ConfirmedFacts) == 0 || rep.Consistency.State == "" {
		t.Fatal("host facts / consistency must be kept on invalid answers")
	}
}

func TestRun_TimeoutPartialReport(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	stub := stubDocker(t, `#!/bin/sh
case "$1" in
  create) echo deadbeefcafe ;;
  start) exec sleep 60 ;;
  cp) echo 'partial agent output' > "$3" ;;
  *) exit 0 ;;
esac
`)

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	rep, err := Run(ctx, Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out,
		NoNet: true, AllowAgent: true, DockerBin: stub, Timeout: 1,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Run.Status != "timeout" {
		t.Fatalf("run status = %s", rep.Run.Status)
	}
	if rep.ResearchState != "incomplete" || rep.Mode != "failed" {
		t.Fatalf("state=%s mode=%s", rep.ResearchState, rep.Mode)
	}
	runDir := filepath.Join(out, "runs", rep.RunID)
	// The partial raw answer is kept even though the container was killed.
	if b, err := os.ReadFile(filepath.Join(runDir, "raw_agent_output.txt")); err != nil ||
		!strings.Contains(string(b), "partial agent output") {
		t.Fatalf("partial raw answer lost: %v", err)
	}
	for _, name := range []string{"report.json", "report.md", "audit.json"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
}

func TestRun_RunScopedNoOverwrite(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		DryRun:        true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	}
	rep1, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	md1 := string(mustRead(t, filepath.Join(out, "runs", rep1.RunID, "report.md")))

	rep2, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if rep2.RunID == rep1.RunID {
		t.Fatalf("two runs share id %s — overwrite risk", rep2.RunID)
	}
	// The first dossier is untouched.
	md1after := string(mustRead(t, filepath.Join(out, "runs", rep1.RunID, "report.md")))
	if md1after != md1 {
		t.Fatal("first run's report.md was overwritten by the second run")
	}
	var idx struct {
		Schema string `json:"schema"`
		Runs   []struct {
			RunID        string `json:"run_id"`
			ReportDir    string `json:"report_dir"`
			RunStatus    string `json:"run_status"`
			SnapshotHash string `json:"snapshot_hash"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(out, "index.json")), &idx); err != nil {
		t.Fatal(err)
	}
	if idx.Schema != "izyan-research-index/1" || len(idx.Runs) != 2 {
		t.Fatalf("index = %+v", idx)
	}
	if idx.Runs[0].RunID != rep1.RunID || idx.Runs[1].RunID != rep2.RunID {
		t.Fatalf("index order/ids wrong: %+v", idx.Runs)
	}
	if idx.Runs[0].SnapshotHash == "" || idx.Runs[0].RunStatus != "planned" {
		t.Fatalf("index entry incomplete: %+v", idx.Runs[0])
	}
}

func TestRun_AdvisoryStoredInDossier(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		DryRun:        true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	runDir := filepath.Join(out, "runs", rep.RunID)
	stored := filepath.Join(runDir, "advisory", "GO-2024-3333.json")
	if b, err := os.ReadFile(stored); err != nil || !strings.Contains(string(b), "GO-2024-3333") {
		t.Fatalf("advisory bytes not stored in the run dossier: %v", err)
	}
	if rep.Advisory.Path != stored {
		t.Fatalf("advisory path = %s, want the dossier copy %s", rep.Advisory.Path, stored)
	}
	if rep.Artifacts["advisory_document"] != filepath.Join("advisory", "GO-2024-3333.json") {
		t.Fatalf("advisory artifact = %q", rep.Artifacts["advisory_document"])
	}
	if len(rep.Advisory.Affected) != 1 || rep.Advisory.Affected[0].Module != "example.com/dep" {
		t.Fatalf("advisory affected entries missing: %+v", rep.Advisory.Affected)
	}
	// The consistency layer ran against the stored advisory.
	if rep.Consistency.State != "assessed" || len(rep.Consistency.Entries) != 1 {
		t.Fatalf("consistency = %+v", rep.Consistency)
	}
	e := rep.Consistency.Entries[0]
	if e.Presence != "present" || e.RangeStatus != "in_range" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestPresenceCheckWording(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := t.TempDir()
	raw := `{"category":"code_not_reachable","reasoning":"pkg/x.go:2 holds the vulnerable function, never reachable."}`
	if err := os.WriteFile(filepath.Join(out, "raw_agent_output.txt"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := &Report{
		Schema: "izyan-research/2", Mode: "executed", RunID: "t", Disclaimer: disclaimer,
		Request:   RequestInfo{SnapshotDir: snap, CVE: "CVE-1-1"},
		Artifacts: map[string]string{},
		Analysis: Analysis{
			Assumptions: ExtractionList{State: "not_assessed"},
			Unknowns:    ExtractionList{State: "not_assessed"},
		},
	}
	rep.Run.Status = "ok"
	analyzeAnswer(Options{SnapshotDir: snap}, rep, out)
	md := renderMarkdown(rep)

	if !strings.Contains(md, "Citation presence check") {
		t.Fatal("presence-check section missing")
	}
	if !strings.Contains(md, "does not confirm the claim") {
		t.Fatal("presence check must state it does not confirm the claim")
	}
	if !strings.Contains(md, "present in snapshot") {
		t.Fatal("found citations must be labelled as presence only")
	}
	if strings.Contains(md, "verified citations") || strings.Contains(md, "ref: `") {
		t.Fatal("old verification wording leaked")
	}
}

func TestSummaryBlockContents(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := stubDocker(t, strings.Replace(dockerStubOK, "AGENT_STDOUT_PAYLOAD",
		`{"category":"requires_configuration","reasoning":"example.com/dep is vulnerable only behind a flag. pkg/x.go:2 is the sink."}`, 1))

	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		AllowAgent: true, DockerBin: stub,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	runDir := filepath.Join(out, "runs", rep.RunID)
	md := string(mustRead(t, filepath.Join(runDir, "report.md")))

	iSummary := strings.Index(md, "## Summary")
	iCategory := strings.Index(md, "## Research category")
	if iSummary < 0 || iSummary > iCategory {
		t.Fatal("summary block must open the report before the category section")
	}
	for _, want := range []string{
		"Vulnerability mechanism", "Found in this product", "Confirmed by host facts",
		"Agent claims", "Critical unknowns", "Secondary unknowns",
		"not assessed by host facts", "What to check or fix",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("summary missing %q", want)
		}
	}
	// The safe-category disclaimer names the categories and denies
	// established safety.
	if !strings.Contains(md, "requires_configuration") ||
		!strings.Contains(md, "perimeter_protected") ||
		!strings.Contains(md, "not an established safety result") {
		t.Fatal("non-vulnerable-category disclaimer missing or watered down")
	}
	// The non-vulnerable category is flagged as unconfirmed; presence
	// facts may never appear to refute it.
	if !strings.Contains(md, "reachability_not_established") {
		t.Fatal("reachability_not_established finding not rendered")
	}
	if strings.Contains(md, "contradiction") {
		t.Fatal("obsolete contradiction wording leaked")
	}
}

// cveOnlyAdvisory mirrors the CVE-2023-44487 shape that broke slice 2:
// affected[] entries with package null (CPE/GIT) and no Go module — the
// Go-ecosystem entries live only in the alias document.
const cveOnlyAdvisory = `{
  "id": "CVE-2023-44487",
  "aliases": ["GO-2023-2153", "GHSA-qppj-fm5r-hxr3"],
  "summary": "HTTP/2 rapid reset",
  "affected": [
    {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]},
    {"package": {"name": "io.grpc:grpc-go", "ecosystem": "Maven"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.58.3"}]}]}
  ]
}`

const goAdvisoryXNet = `{
  "id": "GO-2023-2153",
  "aliases": ["CVE-2023-44487"],
  "summary": "HTTP/2 rapid reset in x/net",
  "affected": [{
    "package": {"name": "golang.org/x/net", "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.17.0"}]}],
    "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/http2", "symbols": ["Server.ServeConn"]}]}
  }]
}`

// An advisory whose affected[] carries no Go module must never emit
// coverage_incomplete — there is nothing comparable to cover.
func TestAdvisory_UncomparableNoCoverage(t *testing.T) {
	root := t.TempDir()
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire golang.org/x/net v0.15.0\n",
	})
	adv := filepath.Join(root, "CVE-2023-44487.json")
	if err := os.WriteFile(adv, []byte(cveOnlyAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2023-44487", OutDir: filepath.Join(root, "out"),
		AdvisoryPath: adv, DryRun: true, NoNet: true,
		Commit:        "0123456789abcdef0123456789abcdef01234567",
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Consistency.State != "not_assessed" {
		t.Fatalf("state = %s", rep.Consistency.State)
	}
	if !strings.Contains(rep.Consistency.Reason, "advisory_uncomparable") {
		t.Fatalf("reason must state advisory_uncomparable: %q", rep.Consistency.Reason)
	}
	for _, f := range rep.Consistency.Findings {
		if f.Kind == "coverage_incomplete" {
			t.Fatalf("no Go entries ⇒ coverage cannot be judged: %+v", f)
		}
	}
	if rep.Advisory.UncomparableEntries != 2 {
		t.Fatalf("uncomparable_entries = %d, want 2", rep.Advisory.UncomparableEntries)
	}
}

// A CVE-only local advisory resolves its Go entries through a sibling
// alias document — offline, the deterministic lane's candidate list.
func TestAdvisory_EcosystemAliasFromSibling(t *testing.T) {
	root := t.TempDir()
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire golang.org/x/net v0.15.0\n",
	})
	advDir := filepath.Join(root, "adv")
	if err := os.MkdirAll(advDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(advDir, "CVE-2023-44487.json"), []byte(cveOnlyAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(advDir, "GO-2023-2153.json"), []byte(goAdvisoryXNet), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2023-44487", OutDir: filepath.Join(root, "out"),
		AdvisoryPath: filepath.Join(advDir, "CVE-2023-44487.json"),
		DryRun:       true, NoNet: true,
		Commit:        "0123456789abcdef0123456789abcdef01234567",
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Consistency.State != "assessed" {
		t.Fatalf("state = %s (reason %s)", rep.Consistency.State, rep.Consistency.Reason)
	}
	e := entryByModule(rep.Consistency, "golang.org/x/net")
	if e == nil {
		t.Fatalf("x/net entry missing: %+v", rep.Consistency.Entries)
	}
	if e.Presence != "present" || e.RangeStatus != "in_range" {
		t.Fatalf("x/net must be present in range: %+v", e)
	}
	if e.DocumentID != "GO-2023-2153" {
		t.Fatalf("entry not linked to ecosystem document: %+v", e)
	}
	var eco *AffectedEntry
	for i := range rep.Advisory.Affected {
		if rep.Advisory.Affected[i].Module == "golang.org/x/net" {
			eco = &rep.Advisory.Affected[i]
		}
	}
	if eco == nil || eco.Document.ID != "GO-2023-2153" || eco.Document.SHA256 == "" {
		t.Fatalf("affected entry must carry its document: %+v", rep.Advisory.Affected)
	}
	runDir := filepath.Join(filepath.Join(root, "out"), "runs", rep.RunID)
	for _, name := range []string{"CVE-2023-44487.json", "GO-2023-2153.json"} {
		if _, err := os.Stat(filepath.Join(runDir, "advisory", name)); err != nil {
			t.Fatalf("dossier missing %s: %v", name, err)
		}
	}
}

// The OSV path: aliases of the primary document are fetched when no Go
// entry is declared — bounded and recorded in advisory.documents.
func TestAdvisory_EcosystemAliasFetch(t *testing.T) {
	root := t.TempDir()
	adv := filepath.Join(root, "CVE-2023-44487.json")
	if err := os.WriteFile(adv, []byte(cveOnlyAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		if strings.HasSuffix(rq.URL.Path, "/v1/vulns/GO-2023-2153") {
			w.Write([]byte(goAdvisoryXNet))
			return
		}
		http.NotFound(w, rq)
	}))
	defer srv.Close()

	runDir := filepath.Join(root, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	res := resolveAdvisory(context.Background(), Options{
		CVE: "CVE-2023-44487", AdvisoryPath: adv, OSVURL: srv.URL,
	}, runDir)

	if len(res.affected) != 1 || res.affected[0].am.Module != "golang.org/x/net" {
		t.Fatalf("affected = %+v", res.affected)
	}
	if res.affected[0].doc.ID != "GO-2023-2153" || res.affected[0].doc.URL == "" {
		t.Fatalf("entry doc = %+v", res.affected[0].doc)
	}
	if len(res.info.Documents) != 2 || res.info.Documents[1].Role != "ecosystem" {
		t.Fatalf("documents = %+v", res.info.Documents)
	}
	if _, err := os.Stat(filepath.Join(runDir, "advisory", "GO-2023-2153.json")); err != nil {
		t.Fatalf("fetched doc not stored: %v", err)
	}
}

// safe_category_unsupported fires for a non-vulnerable category when the
// answer verified no citation inside the snapshot — even with a
// comparable advisory and no contradiction.
func TestConsistency_SafeCategoryUnsupportedNoCitations(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.5.0\n",
	})
	r, ares := consistencyFixture(snap, "code_not_reachable",
		"The vulnerable function is never invoked from the entrypoint.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, ares)

	fs := findingsOf(cr, "safe_category_unsupported")
	if len(fs) != 1 {
		t.Fatalf("want 1 safe_category_unsupported, got %+v", cr.Findings)
	}
	for _, want := range []string{"cannot confirm", "not treated as exhaustive", "not proof that no exploitation path exists"} {
		if !strings.Contains(fs[0].Statement, want) {
			t.Fatalf("finding must carry %q: %s", want, fs[0].Statement)
		}
	}
}

// The finding also fires when the advisory gave nothing comparable — a
// non-vulnerable answer then has zero host backing at all.
func TestConsistency_SafeCategoryUnsupportedUncomparable(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n",
	})
	r, _ := consistencyFixture(snap, "false_positive",
		"The CVE does not apply because pkg/dep/x.go:7 is not present.")
	r.Analysis.PresenceSummary.PathsFound = 1 // cited path verified
	ares := advisoryResult{
		info:         AdvisoryInfo{Status: "resolved", ID: "CVE-1-1"},
		uncomparable: 3,
		primaryDoc:   AdvisoryDocument{Role: "primary", ID: "CVE-1-1"},
	}
	cr := assessConsistency(Options{SnapshotDir: snap}, r, ares)

	if cr.State != "not_assessed" || !strings.Contains(cr.Reason, "advisory_uncomparable") {
		t.Fatalf("state = %s reason %q", cr.State, cr.Reason)
	}
	fs := findingsOf(cr, "safe_category_unsupported")
	if len(fs) != 1 || !strings.Contains(fs[0].Statement, "no comparable Go affected entry") {
		t.Fatalf("want uncomparable safe_category_unsupported, got %+v", cr.Findings)
	}
}

// A non-vulnerable answer is unsupported even when citations verified and
// no contradiction exists — the host's checks can never establish safety.
func TestConsistency_SafeCategoryWithVerifiedCitations(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod":  "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.5.0\n",
		"main.go": "package main\n",
	})
	r, ares := consistencyFixture(snap, "code_not_reachable",
		"example.com/dep v1.5.0 is fixed; the sink at main.go:1 is never called.")
	r.Analysis.PresenceSummary.PathsFound = 1
	cr := assessConsistency(Options{SnapshotDir: snap}, r, ares)
	fs := findingsOf(cr, "safe_category_unsupported")
	if len(fs) != 1 {
		t.Fatalf("every non-vulnerable category must be flagged, got %+v", cr.Findings)
	}
	if !strings.Contains(fs[0].Statement, "1 cited path(s) were verified present") {
		t.Fatalf("grounds must enumerate verified citations: %s", fs[0].Statement)
	}
	if !strings.Contains(fs[0].Statement, "None of these checks establishes safety") {
		t.Fatalf("statement must bound what the checks prove: %s", fs[0].Statement)
	}
}

// Every non-vulnerable category carries the standing limitation in the
// summary — whether or not the finding fired.
func TestSummary_SafeCategoryAlwaysStated(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod":  "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.5.0\n",
		"main.go": "package main\n",
	})
	r, ares := consistencyFixture(snap, "code_not_reachable",
		"example.com/dep v1.5.0 is fixed; the sink at main.go:1 is never called.")
	r.Analysis.PresenceSummary.PathsFound = 1
	r.Run.Status = "ok"
	r.Advisory.Status = "resolved"
	r.Consistency = assessConsistency(Options{SnapshotDir: snap}, r, ares)

	md := renderMarkdown(r)
	if !strings.Contains(md, "the host does not treat the advisory's affected list as exhaustive") {
		t.Fatal("summary must always state the advisory list is not exhaustive for safe categories")
	}
	if !strings.Contains(md, "is a research judgement, not an established safety result") {
		t.Fatal("summary must mark the category as a judgement")
	}
	// A vulnerable category must not get the safe-category limitation.
	r2, ares2 := consistencyFixture(snap, "vulnerable", "example.com/dep is exploited.")
	r2.Run.Status = "ok"
	r2.Advisory.Status = "resolved"
	r2.Consistency = assessConsistency(Options{SnapshotDir: snap}, r2, ares2)
	md2 := renderMarkdown(r2)
	if strings.Contains(md2, "the host does not treat the advisory's affected list as exhaustive") {
		t.Fatal("safe-category limitation leaked onto a vulnerable category")
	}
}

// A fixed (out-of-range) installed version is a version fact — never a
// category and never a reason to substitute the agent's answer.
func TestConsistency_FixedVersionNeverBecomesCategory(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.5.0\n",
	})

	// Non-vulnerable category + out-of-range module: the category stays
	// verbatim, out_of_range must not be turned into a code_not_present
	// or a contradiction.
	r, vuln := consistencyFixture(snap, "false_positive", "example.com/dep here is already fixed.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)
	e := entryByModule(cr, "example.com/dep")
	if e.RangeStatus != "out_of_range" {
		t.Fatalf("entry = %+v", e)
	}
	for _, f := range cr.Findings {
		if f.Kind == "category_absence_tension" || f.Kind == "contradiction" {
			t.Fatalf("out_of_range must not synthesize a category claim: %+v", f)
		}
	}
	if r.Answer.Category != "false_positive" {
		t.Fatalf("category substituted: %q", r.Answer.Category)
	}

	// No parsed answer: version status stands alone; nothing implies a
	// category.
	r2, vuln2 := consistencyFixture(snap, "", "")
	cr2 := assessConsistency(Options{SnapshotDir: snap}, r2, vuln2)
	e2 := entryByModule(cr2, "example.com/dep")
	if e2 == nil || e2.RangeStatus != "out_of_range" {
		t.Fatalf("entry = %+v", e2)
	}
	if len(cr2.Findings) != 0 {
		t.Fatalf("no answer → no findings: %+v", cr2.Findings)
	}
	md := renderMarkdown(&Report{
		Schema: "izyan-research/2", RunID: "t", Disclaimer: disclaimer,
		Request: RequestInfo{CVE: "CVE-1-1"}, Consistency: cr2,
		Answer: AnswerInfo{CategoryLabel: "unavailable"},
	})
	if !strings.Contains(md, "no usable category") {
		t.Fatal("report must state the agent produced no usable category")
	}
	if !strings.Contains(md, "never establish, refute or substitute the category") {
		t.Fatal("report must state version facts never substitute the category")
	}
}

// reachability_not_established fires for non-vulnerable categories whose
// answer provides no confirmed condition/transition — recorded claims
// are unconfirmed (citation checks are presence checks only).
func TestConsistency_ReachabilityNotEstablished(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
	})
	r, vuln := consistencyFixture(snap, "code_not_reachable",
		"The sink in example.com/dep is never reached.")
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)
	fs := findingsOf(cr, "reachability_not_established")
	if len(fs) != 1 {
		t.Fatalf("want 1 reachability_not_established, got %+v", cr.Findings)
	}
	if !strings.Contains(fs[0].Statement, "UNKNOWN") ||
		!strings.Contains(fs[0].Statement, "presence or resolved version") {
		t.Fatalf("finding must keep the status UNKNOWN and bound the host facts: %q", fs[0].Statement)
	}

	// Agent-recorded condition statements do not count as confirmed.
	r2, vuln2 := consistencyFixture(snap, "mitigating_control_protected",
		"example.com/dep is gated by a flag.")
	r2.Analysis.ExploitationConditions = []Claim{{Text: "requires a flag", PathsFound: []string{"main.go:1"}}}
	cr2 := assessConsistency(Options{SnapshotDir: snap}, r2, vuln2)
	fs2 := findingsOf(cr2, "reachability_not_established")
	if len(fs2) != 1 || !strings.Contains(fs2[0].Statement, "unconfirmed agent claims") {
		t.Fatalf("claims are unconfirmed evidence, not confirmation: %+v", cr2.Findings)
	}

	// A vulnerable category is not flagged: reachability UNKNOWN concerns
	// non-vulnerable judgements only.
	r3, vuln3 := consistencyFixture(snap, "vulnerable", "example.com/dep is reachable.")
	cr3 := assessConsistency(Options{SnapshotDir: snap}, r3, vuln3)
	if fs3 := findingsOf(cr3, "reachability_not_established"); len(fs3) != 0 {
		t.Fatalf("vulnerable category must not get reachability_not_established: %+v", fs3)
	}
}

// mechanism_alignment_not_established fires when the agent's mechanism
// text does not name the advisory's affected module/package — including
// when the extraction produced no mechanism at all.
func TestConsistency_MechanismAlignment(t *testing.T) {
	snap := writeTree(t, map[string]string{
		"go.mod": "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
	})

	// Mechanism naming the affected module → no finding.
	r, vuln := consistencyFixture(snap, "vulnerable",
		"example.com/dep's Open() is exploitable.")
	r.Analysis.Mechanism = "The bug is in example.com/dep Open()."
	cr := assessConsistency(Options{SnapshotDir: snap}, r, vuln)
	if fs := findingsOf(cr, "mechanism_alignment_not_established"); len(fs) != 0 {
		t.Fatalf("naming the affected module must not flag: %+v", fs)
	}

	// Mechanism about an unrelated component → flagged.
	r2, vuln2 := consistencyFixture(snap, "vulnerable",
		"recovery middleware recovers panics.")
	r2.Analysis.Mechanism = "grpc_recovery.UnaryServerInterceptor (panic recovery)"
	cr2 := assessConsistency(Options{SnapshotDir: snap}, r2, vuln2)
	fs2 := findingsOf(cr2, "mechanism_alignment_not_established")
	if len(fs2) != 1 || !strings.Contains(fs2[0].Statement, "example.com/dep") {
		t.Fatalf("unrelated mechanism must flag and name the advisory entries: %+v", cr2.Findings)
	}

	// Empty mechanism → flagged as "no description to compare".
	r3, vuln3 := consistencyFixture(snap, "vulnerable", "nothing stated.")
	cr3 := assessConsistency(Options{SnapshotDir: snap}, r3, vuln3)
	fs3 := findingsOf(cr3, "mechanism_alignment_not_established")
	if len(fs3) != 1 || !strings.Contains(fs3[0].Statement, "no mechanism description") {
		t.Fatalf("empty mechanism must flag: %+v", cr3.Findings)
	}

	// A cited vendor path naming the module satisfies the lexical rule.
	r4, vuln4 := consistencyFixture(snap, "vulnerable",
		"vendor/example.com/dep/open.go:7 wraps the call.")
	r4.Analysis.Mechanism = "The vulnerable code is vendor/example.com/dep/open.go:7."
	cr4 := assessConsistency(Options{SnapshotDir: snap}, r4, vuln4)
	if fs4 := findingsOf(cr4, "mechanism_alignment_not_established"); len(fs4) != 0 {
		t.Fatalf("vendor path naming the module must satisfy the rule: %+v", fs4)
	}
}

// --replay-run re-renders a stored dossier: identical answer text and
// identity blocks, recomputed consistency, original directory untouched.
func TestReplayRun_ReRendersStoredRun(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	answer := `{"category":"code_not_reachable","reasoning":"example.com/dep is required but its Open sink is never invoked from main."}`
	export := `{"messages":[{"info":{"role":"assistant"},"parts":[{"type":"text","text":` +
		mustJSONRaw(t, answer) + `}]}]}`
	stub := stubDocker(t, strings.Replace(dockerStubOK, "AGENT_STDOUT_PAYLOAD", export, 1))

	orig, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		AllowAgent: true, DockerBin: stub,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	origDir := filepath.Join(out, "runs", orig.RunID)
	origJSON := mustRead(t, filepath.Join(origDir, "report.json"))
	origMD := mustRead(t, filepath.Join(origDir, "report.md"))

	rep, err := Run(context.Background(), Options{ReplayRun: origDir})
	if err != nil {
		t.Fatalf("ReplayRun: %v", err)
	}
	if rep.RerenderOf != orig.RunID || rep.RunID == orig.RunID {
		t.Fatalf("rerender linkage wrong: %s -> %s", rep.RunID, rep.RerenderOf)
	}
	if rep.Answer.Category != orig.Answer.Category ||
		rep.Answer.Reasoning != orig.Answer.Reasoning || !rep.Answer.Parsed {
		t.Fatalf("replay must reproduce the stored answer verbatim: %+v vs %+v",
			rep.Answer, orig.Answer)
	}
	// Identity blocks are verbatim.
	if !reflect.DeepEqual(rep.Snapshot, orig.Snapshot) ||
		!reflect.DeepEqual(rep.Advisory, orig.Advisory) ||
		!reflect.DeepEqual(rep.Prompt, orig.Prompt) ||
		!reflect.DeepEqual(rep.Run, orig.Run) ||
		!reflect.DeepEqual(rep.Request, orig.Request) ||
		rep.Mode != orig.Mode {
		t.Fatal("identity blocks must be copied verbatim")
	}
	// Host facts recomputed from the snapshot.
	if len(rep.Consistency.Entries) != 1 ||
		rep.Consistency.Entries[0].Presence != "present" ||
		rep.Consistency.Entries[0].RangeStatus != "in_range" {
		t.Fatalf("consistency not recomputed: %+v", rep.Consistency)
	}
	if len(findingsOf(rep.Consistency, "reachability_not_established")) != 1 {
		t.Fatalf("new findings vocabulary missing: %+v", rep.Consistency.Findings)
	}
	newDir := filepath.Join(out, "runs", rep.RunID)
	for _, name := range []string{"report.json", "report.md", "audit.json",
		"raw_agent_output.txt", "prompt.txt", "advisory/GO-2024-3333.json"} {
		if _, err := os.Stat(filepath.Join(newDir, name)); err != nil {
			t.Fatalf("re-rendered dossier missing %s: %v", name, err)
		}
	}
	// The original dossier is byte-untouched.
	if !bytes.Equal(mustRead(t, filepath.Join(origDir, "report.json")), origJSON) ||
		!bytes.Equal(mustRead(t, filepath.Join(origDir, "report.md")), origMD) {
		t.Fatal("original run directory was modified")
	}
	// The report states the replay provenance.
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, filepath.Join(newDir, "report.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["rerender_of"] != orig.RunID {
		t.Fatalf("rerender_of missing: %v", doc)
	}
	md := string(mustRead(t, filepath.Join(newDir, "report.md")))
	if !strings.Contains(md, "no model call was made") {
		t.Fatal("report.md must state no model call was made")
	}

	// index.json lists both runs; the replay carries rerender_of.
	var idx struct {
		Runs []IndexEntry `json:"runs"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(out, "index.json")), &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Runs) != 2 || idx.Runs[1].RerenderOf != orig.RunID {
		t.Fatalf("index = %+v", idx.Runs)
	}
}

// --replay-run on a dossier whose recorded snapshot path no longer
// exists fails with an explicit error naming the missing input.
func TestReplayRun_MissingSnapshotFails(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out, AdvisoryPath: adv,
		DryRun:        true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	runDir := filepath.Join(out, "runs", rep.RunID)
	if err := os.RemoveAll(snap); err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), Options{ReplayRun: runDir})
	if err == nil || !strings.Contains(err.Error(), "snapshot") ||
		!strings.Contains(err.Error(), snap) {
		t.Fatalf("replay must fail naming the missing snapshot: %v", err)
	}
}

func mustJSONRaw(t *testing.T, s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

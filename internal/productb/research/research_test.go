package research

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeSnapshot builds a minimal pinned tree: a SHA-named dir with go.mod
// and one source file — the benchmark snapshot layout without .git.
func writeSnapshot(t *testing.T, parent string) string {
	t.Helper()
	dir := filepath.Join(parent, "0123456789abcdef0123456789abcdef01234567")
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":   "module example.com/prod\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
		"go.sum":   "example.com/dep v1.2.3 h1:abc=\nexample.com/dep v1.2.3/go.mod h1:def=\n",
		"main.go":  "package main\n\nfunc main() {}\n",
		"pkg/x.go": "package pkg\n\nfunc X() {}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const testAdvisory = `{
  "id": "GO-2024-3333",
  "aliases": ["CVE-2024-32473"],
  "summary": "test advisory for the dep module",
  "modified": "2024-04-18T00:00:00Z",
  "affected": [{
    "package": {"name": "example.com/dep", "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}],
    "ecosystem_specific": {"imports": [{"path": "example.com/dep", "symbols": ["Open"]}]}
  }],
  "references": [{"type": "ADVISORY", "url": "https://example.com/adv"}]
}`

func stubDigest(image string) string {
	return "sha256:91629799d07a08fc56e36fe1d51589cf3a1f24ff73ed9e09bad0331161703c13"
}

func TestRun_DryRun(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), Options{
		SnapshotDir:  snap,
		CVE:          "CVE-2024-32473",
		OutDir:       out,
		AdvisoryPath: adv,
		DryRun:       true,
		DigestFetcher: func(_ context.Context, image string) (string, error) {
			return stubDigest(image), nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Mode != "dry_run" || rep.Run.Status != "planned" {
		t.Fatalf("mode=%s run=%s, want dry_run/planned", rep.Mode, rep.Run.Status)
	}
	if rep.Snapshot.Commit != "0123456789abcdef0123456789abcdef01234567" ||
		rep.Snapshot.IdentitySource != "directory_basename" {
		t.Fatalf("snapshot identity: %+v", rep.Snapshot)
	}
	if rep.Snapshot.ContentHash == "" {
		t.Fatal("content hash missing")
	}
	if rep.Snapshot.Module.ModulePath != "example.com/prod" || rep.Snapshot.Module.RequireCount != 1 {
		t.Fatalf("module graph: %+v", rep.Snapshot.Module)
	}
	if rep.Advisory.Status != "resolved" || rep.Advisory.ID != "GO-2024-3333" {
		t.Fatalf("advisory: %+v", rep.Advisory)
	}
	if rep.Advisory.SHA256 == "" {
		t.Fatal("advisory digest missing")
	}
	if rep.Answer.CategoryLabel != "unavailable" {
		t.Fatalf("dry-run must not invent a category: %+v", rep.Answer)
	}

	// Plan artifacts exist inside the run-scoped dir; nothing was launched.
	runDir := filepath.Join(out, "runs", rep.RunID)
	for _, name := range []string{"report.json", "report.md", "audit.json", "prompt.txt", "opencode-config.json"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "index.json")); err != nil {
		t.Fatalf("index.json missing: %v", err)
	}
	prompt, _ := os.ReadFile(filepath.Join(runDir, "prompt.txt"))
	if !strings.Contains(string(prompt), "CVE-2024-32473") || strings.Contains(string(prompt), "{cve_id}") {
		t.Fatal("prompt.txt not the rendered template")
	}
	var cfg map[string]any
	if err := json.Unmarshal(mustRead(t, filepath.Join(runDir, "opencode-config.json")), &cfg); err != nil {
		t.Fatal(err)
	}
	if _, has := cfg["mcp"]; has {
		t.Fatal("config carries an mcp block")
	}
	tools, _ := cfg["tools"].(map[string]any)
	if tools["task"] != false {
		t.Fatal("task tool not disabled")
	}
	// argv recorded, mounts read-only
	if len(rep.Run.Argv) == 0 || rep.Run.Argv[0] != "docker" {
		t.Fatalf("argv not recorded: %v", rep.Run.Argv)
	}
	foundRO := 0
	for _, m := range rep.Run.Mounts {
		if m.Mode != "ro" {
			t.Fatalf("mount %s not read-only", m.Container)
		}
		foundRO++
	}
	if foundRO != 3 {
		t.Fatalf("want 3 ro mounts, got %d", foundRO)
	}

	// Report skeleton: disclaimer + sections present, no verdict/auto-close.
	md := string(mustRead(t, filepath.Join(runDir, "report.md")))
	assertReportSkeleton(t, md)
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, filepath.Join(runDir, "report.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if _, has := doc["verdict"]; has {
		t.Fatal("report.json carries a verdict field — forbidden")
	}
	if doc["schema"] != "izyan-research/2" {
		t.Fatalf("schema: %v", doc["schema"])
	}
}

func TestRun_NoAllowAgentIsPlannedOnly(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473", OutDir: out,
		NoNet:         true,
		AllowAgent:    false,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Mode != "planned" || rep.Run.Status != "skipped" {
		t.Fatalf("mode=%s run=%s", rep.Mode, rep.Run.Status)
	}
	if rep.Advisory.Status != "skipped_no_net" {
		t.Fatalf("advisory: %+v", rep.Advisory)
	}
	if len(rep.Analysis.Unknowns.Items) == 0 {
		t.Fatal("advisory gap not recorded as unknown")
	}
}

func TestRun_MissingAdvisory(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	for _, tc := range []struct {
		name string
		path string
	}{
		{"missing_file", filepath.Join(root, "does-not-exist.json")},
		{"empty_dir", filepath.Join(root, "empty-adv")},
	} {
		if tc.name == "empty_dir" {
			if err := os.MkdirAll(tc.path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Run(context.Background(), Options{
				SnapshotDir: snap, CVE: "CVE-2024-32473",
				OutDir:       filepath.Join(root, "out-"+tc.name),
				AdvisoryPath: tc.path, DryRun: true,
				DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
			})
			if err != nil {
				t.Fatalf("Run must survive a missing advisory: %v", err)
			}
			if rep.Advisory.Status == "resolved" {
				t.Fatalf("advisory wrongly resolved: %+v", rep.Advisory)
			}
			if rep.Advisory.Reason == "" {
				t.Fatal("gap reason not recorded")
			}
			joined := strings.Join(rep.Analysis.Unknowns.Items, " ")
			if !strings.Contains(joined, "advisory") {
				t.Fatalf("unknowns missing advisory gap: %v", rep.Analysis.Unknowns.Items)
			}
		})
	}
}

func TestRun_MismatchedAdvisory(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	adv := filepath.Join(root, "other.json")
	// Valid OSV doc, different id and no matching alias.
	if err := os.WriteFile(adv, []byte(`{"id":"GO-2020-0001","affected":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473",
		OutDir: filepath.Join(root, "out"), AdvisoryPath: adv, DryRun: true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Advisory.Status != "unavailable" {
		t.Fatalf("advisory: %+v", rep.Advisory)
	}
}

func TestRun_AdvisoryDir(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	advDir := filepath.Join(root, "advs")
	if err := os.MkdirAll(advDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(advDir, "unrelated.json"), []byte(`{"id":"GO-2020-0001","affected":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(advDir, "match.json"), []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473",
		OutDir: filepath.Join(root, "out"), AdvisoryPath: advDir, DryRun: true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Advisory.Status != "resolved" || rep.Advisory.ID != "GO-2024-3333" {
		t.Fatalf("dir scan failed: %+v", rep.Advisory)
	}
}

func TestRun_SnapshotWithoutIdentityFails(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, "not-a-sha-dir")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Options{
		SnapshotDir: bad, CVE: "CVE-1-1", OutDir: filepath.Join(root, "o"),
		DryRun:        true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err == nil || !strings.Contains(err.Error(), "--commit") {
		t.Fatalf("expected identity error mentioning --commit, got %v", err)
	}
	// --commit supplies the identity.
	rep, err := Run(context.Background(), Options{
		SnapshotDir: bad, CVE: "CVE-1-1", OutDir: filepath.Join(root, "o2"),
		Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DryRun: true, NoNet: true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	})
	if err != nil {
		t.Fatalf("Run with --commit: %v", err)
	}
	if rep.Snapshot.IdentitySource != "--commit" {
		t.Fatalf("identity source: %s", rep.Snapshot.IdentitySource)
	}
}

func TestReportSeparationAndLabelling(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"category":"code_not_reachable","reasoning":"The vulnerability is a path traversal. pkg/x.go:2 reads it. It is never reachable from main. I assume CGO is off. Cannot determine exploitability end-to-end."}`
	if err := os.WriteFile(filepath.Join(out, "raw_agent_output.txt"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := &Report{
		Schema: "izyan-research/2", GeneratedAt: "now", Tool: "izyan", Command: "research",
		Mode: "executed", ResearchState: "complete", RunID: "test-run", Disclaimer: disclaimer,
		Request:   RequestInfo{SnapshotDir: snap, CVE: "CVE-2024-32473"},
		Artifacts: map[string]string{},
		Analysis: Analysis{
			ConfirmedFacts: []Fact{{Statement: "snapshot commit x", Reference: ".", Source: "snapshot"}},
			Assumptions:    ExtractionList{State: "not_assessed"},
			Unknowns:       ExtractionList{State: "not_assessed"},
		},
	}
	rep.Run.Status = "ok"
	analyzeAnswer(Options{SnapshotDir: snap, OutDir: out}, rep, out)
	md := renderMarkdown(rep)

	assertReportSkeleton(t, md)
	// The three sections appear in order and are non-empty-labelled.
	iFacts := strings.Index(md, "## Confirmed facts")
	iAssum := strings.Index(md, "## Assumptions")
	iUnk := strings.Index(md, "## Unknowns")
	if !(iFacts >= 0 && iFacts < iAssum && iAssum < iUnk) {
		t.Fatalf("section order broken: %d %d %d", iFacts, iAssum, iUnk)
	}
	if !strings.Contains(md, "I assume CGO is off") {
		t.Fatal("assumption sentence missing from Assumptions")
	}
	if !strings.Contains(md, "research_judgement") {
		t.Fatal("research category not labelled as research_judgement")
	}
	// No auto-close / safety-conclusion wording in the produced document.
	for _, banned := range []string{
		"verdict:", "Vulnerability closed", "marked NOT_AFFECTED",
		"is not affected", "auto-close", "automatically closed",
		"safe to ship", "confirmed safe", "cleared",
	} {
		if strings.Contains(strings.ToLower(md), strings.ToLower(banned)) {
			t.Fatalf("report.md contains forbidden closure wording %q", banned)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(mustJSON(t, rep), &doc); err != nil {
		t.Fatal(err)
	}
	if _, has := doc["verdict"]; has {
		t.Fatal("report.json must not carry a verdict field")
	}
	answer := doc["answer"].(map[string]any)
	if answer["category_label"] != "research_judgement" {
		t.Fatalf("category_label: %v", answer["category_label"])
	}
}

func TestSynthesizeConfig_Pins(t *testing.T) {
	_, raw, err := synthesizeConfig(Options{}, "custom-openai/Qwen/Qwen3.6-35B-A3B")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, has := cfg["mcp"]; has {
		t.Fatal("mcp present")
	}
	if cfg["tools"].(map[string]any)["task"] != false {
		t.Fatal("task tool not disabled")
	}
	prov := cfg["provider"].(map[string]any)["custom-openai"].(map[string]any)
	if prov["options"].(map[string]any)["apiKey"] != "{env:OPENAI_API_KEY}" {
		t.Fatal("apiKey not env-interpolated")
	}
	if prov["options"].(map[string]any)["baseURL"] != "{env:OPENAI_BASE_URL}" {
		t.Fatal("baseURL not env-interpolated")
	}
	if _, ok := prov["models"].(map[string]any)["Qwen/Qwen3.6-35B-A3B"]; !ok {
		t.Fatal("model key missing from provider")
	}
}

func assertReportSkeleton(t *testing.T, md string) {
	t.Helper()
	for _, want := range []string{
		"RESEARCH judgement", "not a verified safety conclusion",
		"automatic closure", "not performed",
		"## Summary", "## Host-fact consistency", "## Citation presence check",
		"## Confirmed facts", "## Assumptions", "## Unknowns",
		"## Snapshot", "## Advisory", "## Agent run",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("report.md missing %q", want)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func factsOf(r *Report) []string {
	out := make([]string, 0, len(r.Analysis.ConfirmedFacts))
	for _, f := range r.Analysis.ConfirmedFacts {
		out = append(out, f.Statement)
	}
	return out
}

func TestDockerCreateArgv_Auditable(t *testing.T) {
	o := Options{AgentImage: DefaultAgentImage, SnapshotDir: "/snap", AgentEnv: []string{"OPENAI_API_KEY"}}
	run := RunInfo{
		ProviderModel:  "custom-openai/Qwen/Qwen3.6-35B-A3B",
		TimeoutSeconds: 900,
		EnvForwarded:   []string{"OPENAI_API_KEY"},
		Mounts: []Mount{
			{Host: "/snap", Container: "/work", Mode: "ro"},
			{Host: "/out/opencode-config.json", Container: "/tmp/.config/opencode/opencode.json", Mode: "ro"},
			{Host: "/out/prompt.txt", Container: "/tmp/prompt.txt", Mode: "ro"},
		},
	}
	argv := dockerCreateArgv(o, run)
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"create", "--workdir /work", "-e OPENAI_API_KEY",
		"/snap:/work:ro", "--entrypoint sh", DefaultAgentImage, "-lc",
		"opencode run --model 'custom-openai/Qwen/Qwen3.6-35B-A3B' --thinking --dangerously-skip-permissions",
		"timeout 900s",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "mcp") {
		t.Fatal("argv mentions mcp")
	}
}

// TestRun_SkipContentHash exercises the eval-only escape: a snapshot the
// default verifier rejects (a symlink escaping the root — the containment
// walk fails) still runs when --skip-content-hash is set; the identity
// stays commit + path, the hash reads "skipped"/"none" and the run
// carries a limitation in report.json/report.md/audit.json. The same
// tree without the flag fails, a clean tree keeps the t1 path, and
// --replay-run copies the stored snapshot identity verbatim regardless
// of the flag.
func TestRun_SkipContentHash(t *testing.T) {
	root := t.TempDir()
	snap := writeSnapshot(t, root)
	adv := filepath.Join(root, "adv.json")
	if err := os.WriteFile(adv, []byte(testAdvisory), 0o644); err != nil {
		t.Fatal(err)
	}

	// A symlink escaping the snapshot root: the default VerifyContained
	// walk fails on it, the skip path never walks the tree at all.
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("foreign bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(snap, "escape.txt")); err != nil {
		t.Fatal(err)
	}

	base := Options{
		SnapshotDir: snap, CVE: "CVE-2024-32473",
		AdvisoryPath: adv, DryRun: true,
		DigestFetcher: func(_ context.Context, _ string) (string, error) { return stubDigest(""), nil },
	}

	// Default path: the containment walk rejects the escaping symlink.
	def := base
	def.OutDir = filepath.Join(root, "out-default")
	if _, err := Run(context.Background(), def); err == nil ||
		!strings.Contains(err.Error(), "containment") {
		t.Fatalf("default verifier must reject the escaping symlink: %v", err)
	}

	// Skip path: no walk happens, so the hostile tree verifies.
	skip := base
	skip.OutDir = filepath.Join(root, "out")
	skip.SkipContentHash = true
	rep, err := Run(context.Background(), skip)
	if err != nil {
		t.Fatalf("Run --skip-content-hash: %v", err)
	}
	if rep.Snapshot.ContentHash != "skipped" || rep.Snapshot.ContentHashAlg != "none" {
		t.Fatalf("snapshot hash block: %+v", rep.Snapshot)
	}
	if rep.Snapshot.Commit != "0123456789abcdef0123456789abcdef01234567" ||
		rep.Snapshot.IdentitySource != "directory_basename" {
		t.Fatalf("identity must stay commit + path: %+v", rep.Snapshot)
	}
	// Toolchain/module-graph facts are retained without the walk.
	if rep.Snapshot.GoModDirective != "1.22" ||
		rep.Snapshot.Module.ModulePath != "example.com/prod" ||
		rep.Snapshot.Module.RequireCount != 1 {
		t.Fatalf("module-graph/toolchain facts lost: %+v", rep.Snapshot)
	}
	foundLimit := false
	for _, l := range rep.Limitations {
		if strings.Contains(l, "--skip-content-hash") {
			foundLimit = true
		}
	}
	if !foundLimit {
		t.Fatalf("limitation missing: %v", rep.Limitations)
	}
	joined := strings.Join(factsOf(rep), " ")
	if !strings.Contains(joined, "content hash skipped by controller flag") ||
		strings.Contains(joined, "canonical content hash t1:") {
		t.Fatalf("confirmed facts do not record the skip: %s", joined)
	}
	for i, f := range rep.Analysis.ConfirmedFacts {
		if f.SnapshotHash != "skipped" {
			t.Fatalf("confirmed fact %d bound to %q, want the recorded hash", i, f.SnapshotHash)
		}
	}

	runDir := filepath.Join(skip.OutDir, "runs", rep.RunID)
	var doc struct {
		Snapshot struct {
			ContentHash    string `json:"content_hash"`
			ContentHashAlg string `json:"content_hash_algorithm"`
		} `json:"snapshot"`
		Limitations []string `json:"limitations"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(runDir, "report.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Snapshot.ContentHash != "skipped" || doc.Snapshot.ContentHashAlg != "none" ||
		len(doc.Limitations) == 0 {
		t.Fatalf("report.json skip markers missing: %+v", doc)
	}
	md := string(mustRead(t, filepath.Join(runDir, "report.md")))
	if !strings.Contains(md, "content hash (none): `skipped`") {
		t.Fatal("report.md does not show the skipped hash")
	}
	var audit struct {
		SnapshotHash string   `json:"snapshot_hash"`
		Limitations  []string `json:"limitations"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(runDir, "audit.json")), &audit); err != nil {
		t.Fatal(err)
	}
	if audit.SnapshotHash != "skipped" || len(audit.Limitations) == 0 {
		t.Fatalf("audit.json skip markers missing: %+v", audit)
	}

	// The default path on a clean tree is unchanged: t1 hash, no
	// limitation.
	clean := writeSnapshot(t, filepath.Join(root, "clean"))
	normal := base
	normal.SnapshotDir = clean
	normal.OutDir = filepath.Join(root, "out-clean")
	repClean, err := Run(context.Background(), normal)
	if err != nil {
		t.Fatalf("clean default run: %v", err)
	}
	if repClean.Snapshot.ContentHashAlg != "t1" ||
		len(repClean.Snapshot.ContentHash) != 64 {
		t.Fatalf("default path changed: %+v", repClean.Snapshot)
	}
	if len(repClean.Limitations) != 0 {
		t.Fatalf("default run gained limitations: %v", repClean.Limitations)
	}

	// Replay copies the stored identity verbatim — the "skipped" dossier
	// stays "skipped" and a t1 dossier stays t1 even when the flag is set.
	repReplay, err := Run(context.Background(), Options{ReplayRun: runDir})
	if err != nil {
		t.Fatalf("replay of the skipped run: %v", err)
	}
	if !reflect.DeepEqual(repReplay.Snapshot, rep.Snapshot) {
		t.Fatalf("replay rewrote the stored snapshot block: %+v", repReplay.Snapshot)
	}
	cleanDir := filepath.Join(normal.OutDir, "runs", repClean.RunID)
	repFlagged, err := Run(context.Background(), Options{ReplayRun: cleanDir, SkipContentHash: true})
	if err != nil {
		t.Fatalf("flagged replay of the t1 run: %v", err)
	}
	if repFlagged.Snapshot.ContentHash != repClean.Snapshot.ContentHash ||
		repFlagged.Snapshot.ContentHashAlg != "t1" {
		t.Fatalf("--replay-run must ignore --skip-content-hash: %+v", repFlagged.Snapshot)
	}
}

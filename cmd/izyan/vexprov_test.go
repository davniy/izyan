package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/eval/vexbench"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

func TestParseGovulnVersion(t *testing.T) {
	out := `Go: go1.26.1
Scanner: govulncheck@v1.1.4
DB: https://vuln.go.dev
DB Updated: 2026-09-30T12:00:00Z
`
	v, url, mod := parseGovulnVersion(out)
	if v != "v1.1.4" || url != "https://vuln.go.dev" || mod != "2026-09-30T12:00:00Z" {
		t.Fatalf("parsed %q %q %q", v, url, mod)
	}
	// Missing lines stay empty — no invented versions.
	v, url, mod = parseGovulnVersion("no fields\n")
	if v != "" || url != "" || mod != "" {
		t.Fatalf("expected empty fields, got %q %q %q", v, url, mod)
	}
}

func TestCollectVexProvenanceFields(t *testing.T) {
	dir := t.TempDir()
	tasksPath := filepath.Join(dir, "vex_bench.jsonl")
	if err := os.WriteFile(tasksPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tasks := []vexbench.Task{
		{TaskID: "a-b-1-CVE-1", RepoURL: "https://github.com/a/b", CommitSHA: "1", CVEID: "CVE-1"},
		{TaskID: "a-b-2-CVE-2", RepoURL: "https://github.com/a/b", CommitSHA: "2", CVEID: "CVE-2"},
	}
	envs := []vexEnvelope{{LLMCalls: 0, ToolCalls: 3, OSVFetches: 2}}

	p := collectVexProvenance(tasksPath, tasks, envs,
		toolchain.Toolchain{Version: "1.26.1", Mode: toolchain.ModeLocal, GoBin: "go"}, os.Args[0], 1)

	if p.AdapterVersion != vexAdapterVersion || p.SchemaVersion != "2" {
		t.Fatalf("adapter version not bumped: %q", p.AdapterVersion)
	}
	if p.IzyanDirty == nil && p.Missing["izyan_dirty"] == "" {
		t.Fatal("izyan_dirty must be a real bool or carry a missing reason")
	}
	if p.TasksSHA256 == "" {
		t.Fatal("tasks_sha256 missing")
	}
	if len(p.TaskIDs) != 2 || p.TotalTasks != 2 || p.UniqueRepos != 1 || p.UniqueSnaps != 2 {
		t.Fatalf("task counts wrong: %+v", p)
	}
	if p.CLIJ != 1 || p.TargetGOOS == "" || p.HostOS == "" {
		t.Fatalf("platform fields missing: %+v", p)
	}
	if p.Model != nil || p.Missing["model"] == "" {
		t.Fatal("model must be null with a not_applicable reason")
	}
	if p.Missing["tokens"] == "" {
		t.Fatal("tokens must carry an explicit missing reason")
	}
	if p.LLMCalls != 0 || p.ToolCalls != 3 || p.OSVFetches != 2 {
		t.Fatalf("usage sums wrong: %+v", p)
	}
	if p.OSVFetchLog == "" {
		t.Fatal("fetch log path must be recorded when fetches exist")
	}
}

func TestCollectVexProvenanceMissingIsExplicit(t *testing.T) {
	// A tasks file that does not exist must produce a missing reason, not a
	// fabricated digest.
	p := collectVexProvenance(filepath.Join(t.TempDir(), "absent.jsonl"), nil, nil,
		toolchain.Toolchain{Version: "x"}, "", 1)
	if p.TasksSHA256 != "" || p.Missing["tasks_sha256"] == "" {
		t.Fatal("absent tasks file must yield missing reason, not a digest")
	}
	if p.Missing["izyan_binary_sha256"] == "" && p.IzyanBinSHA256 == "" {
		t.Fatal("empty self-binary must record a missing reason")
	}
}

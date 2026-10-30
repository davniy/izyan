package vexbench_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/eval/vexbench"
)

func TestLoadGoTasksFiltersAndKeepsOrder(t *testing.T) {
	tasks, err := vexbench.LoadGoTasks(filepath.Join("testdata", "tasks.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 3 {
		t.Fatalf("got %d tasks, want 3 (python filtered out)", len(tasks))
	}
	want := []string{
		"kubernetes-kubernetes-ec78c0f-CVE-2021-3121",
		"labstack-echo-fdacff0-CVE-2020-26160",
		"gitleaks-gitleaks-f487f85-CVE-2025-22871",
	}
	for i, id := range want {
		if tasks[i].TaskID != id {
			t.Fatalf("tasks[%d].TaskID=%q want %q (file order must be stable)", i, tasks[i].TaskID, id)
		}
	}
	first := tasks[0]
	if first.CVEID != "CVE-2021-3121" || first.RepoURL != "https://github.com/kubernetes/kubernetes" {
		t.Fatalf("unexpected task: %+v", first)
	}
	if first.GroundTruth != "exploitable" || first.GroundTruthCategory != "vulnerable" {
		t.Fatalf("labels must stay on the control-plane task: %+v", first)
	}
	if first.PRURL != "https://github.com/kubernetes/kubernetes/pull/101154" {
		t.Fatalf("pr_url not decoded from metadata: %+v", first)
	}
	if tasks[2].RepoURL != "https://github.com/gitleaks/gitleaks.git" {
		t.Fatalf("repo_url changed: %q", tasks[2].RepoURL)
	}
}

func TestLoadGoTasksSkipsBlankLinesAndReportsLineNumber(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "tasks.jsonl")
	content := "{\"task_id\": \"ok\", \"metadata\": {\"language\": \"go\"}}\n\nnot json\n"
	if err := os.WriteFile(bad, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := vexbench.LoadGoTasks(bad)
	if err == nil || !strings.Contains(err.Error(), ":3:") {
		t.Fatalf("want error naming line 3, got %v", err)
	}
}

func TestLoadGoTasksEmptyAndMissing(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(empty, []byte("\n  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tasks, err := vexbench.LoadGoTasks(empty)
	if err != nil || len(tasks) != 0 {
		t.Fatalf("empty file: tasks=%v err=%v", tasks, err)
	}
	if _, err := vexbench.LoadGoTasks(filepath.Join("testdata", "missing.jsonl")); err == nil {
		t.Fatal("missing file: want error")
	}
}

func TestAgentInputForStripsHiddenFields(t *testing.T) {
	task := vexbench.Task{
		TaskID:              "id-1",
		RepoURL:             "https://github.com/o/r",
		CommitSHA:           "abc123",
		CVEID:               "CVE-2099-0001",
		GroundTruth:         "exploitable",
		GroundTruthCategory: "vulnerable",
		PRURL:               "https://github.com/o/r/pull/1",
	}
	in := vexbench.AgentInputFor(task, "/snap/path")
	if in.TaskID != "id-1" || in.CVEID != "CVE-2099-0001" || in.RepoPath != "/snap/path" || in.CommitSHA != "abc123" {
		t.Fatalf("agent input wrong: %+v", in)
	}
	// AgentInput must not leak labels: it has no such fields, and its JSON
	// form must contain neither ground truth nor the reference PR.
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"ground_truth", "exploitable", "pull/1"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("agent input leaks %q: %s", leak, raw)
		}
	}
}

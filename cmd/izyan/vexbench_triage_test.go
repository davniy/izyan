package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedCaseCLINoLabelLeaks(t *testing.T) {
	TestVexTriagePrepareCLI(t)
}

func TestVexTriagePrepareCLI(t *testing.T) {
	repos := t.TempDir()
	advisories := t.TempDir()
	outDir := t.TempDir()

	sha := "ec78c0f95fbe478f6e7a8f70c2b51ad937d6fa02"
	snapDir := filepath.Join(repos, "kubernetes", "kubernetes", sha)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	advContent := `{
		"id": "CVE-2021-3121",
		"modified": "2021-05-15T00:00:00Z",
		"affected": [{
			"package": {"name": "github.com/gonuts/binary", "ecosystem": "Go"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.1.0"}]}]
		}],
		"references": [{"type": "FIX", "url": "https://github.com/gonuts/binary/pull/123"}]
	}`
	if err := os.WriteFile(filepath.Join(advisories, "CVE-2021-3121.json"), []byte(advContent), 0o644); err != nil {
		t.Fatal(err)
	}

	tasksFile := filepath.Join(t.TempDir(), "tasks.jsonl")
	taskLine := `{"repo_url": "https://github.com/kubernetes/kubernetes", "commit_sha": "ec78c0f95fbe478f6e7a8f70c2b51ad937d6fa02", "task_id": "kubernetes-kubernetes-ec78c0f-CVE-2021-3121", "ground_truth_category": "vulnerable", "ground_truth": "exploitable", "cve_id": "CVE-2021-3121", "metadata": {"language": "go", "pr_url": "https://github.com/kubernetes/kubernetes/pull/101154"}}` + "\n"
	if err := os.WriteFile(tasksFile, []byte(taskLine), 0o644); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"prepare",
		"--tasks", tasksFile,
		"--repos-dir", repos,
		"--advisories-dir", advisories,
		"--out", outDir,
	}

	err := runVexTriage(args)
	if err != nil {
		t.Fatalf("runVexTriage prepare failed: %v", err)
	}

	// Verify control-joins.json was created outside finding bundles
	joinsFile := filepath.Join(outDir, "control-joins.json")
	joinsData, err := os.ReadFile(joinsFile)
	if err != nil {
		t.Fatalf("control-joins.json missing: %v", err)
	}
	if !strings.Contains(string(joinsData), "kubernetes-kubernetes-ec78c0f-CVE-2021-3121") {
		t.Fatalf("control-joins.json should hold task ID mapping")
	}

	// Verify manifest
	manifestFile := filepath.Join(outDir, "prepared-cases-manifest.json")
	if _, err := os.Stat(manifestFile); err != nil {
		t.Fatalf("prepared-cases-manifest.json missing: %v", err)
	}

	// Verify case directory exists and has prepared-case.json without label fields
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	foundCase := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "vex-") {
			foundCase = true
			caseJSONPath := filepath.Join(outDir, e.Name(), "prepared-case.json")
			caseData, err := os.ReadFile(caseJSONPath)
			if err != nil {
				t.Fatalf("read case data: %v", err)
			}
			caseStr := string(caseData)
			for _, leak := range []string{"ground_truth", "exploitable", "vulnerable", "pull/101154"} {
				if strings.Contains(caseStr, leak) {
					t.Fatalf("prepared-case.json leaks %q: %s", leak, caseStr)
				}
			}
		}
	}
	if !foundCase {
		t.Fatal("expected at least one vex- prefixed case dir")
	}
}

func TestPrepareCannotExecute(t *testing.T) {
	// Prepare only builds input bundle and manifest, never executes model or arm
	outDir := t.TempDir()
	// Running prepare with invalid flags or tasks doesn't touch execution paths
	err := runVexTriage([]string{"prepare"})
	if err == nil {
		t.Fatal("expected error on missing required prepare flags")
	}
	// Verify no execution artifacts (e.g. vex-triage-run.json) are created
	if _, err := os.Stat(filepath.Join(outDir, "vex-triage-run.json")); !os.IsNotExist(err) {
		t.Fatal("prepare must not emit execution artifacts")
	}
}

func TestExecutionRequiresExplicitAuthorization(t *testing.T) {
	outDir := t.TempDir()
	bundleDir := t.TempDir()

	// Attempt execute without --authorize-execution
	err := runVexTriage([]string{
		"execute",
		"--bundle", bundleDir,
		"--out", outDir,
	})
	if err == nil {
		t.Fatal("expected execute to fail without explicit run authorization flag")
	}
	if !strings.Contains(err.Error(), "explicit run authorization") && !strings.Contains(err.Error(), "authorize") {
		t.Fatalf("expected error mentioning authorization, got: %v", err)
	}
}
func TestVexTriageScoreCLI(t *testing.T) {
	outDir := t.TempDir()
	bundleDir := t.TempDir()
	runsDir := t.TempDir()

	manifestFile := filepath.Join(bundleDir, "prepared-cases-manifest.json")
	if err := os.WriteFile(manifestFile, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runVexTriage([]string{
		"score",
		"--bundle", bundleDir,
		"--runs", runsDir,
		"--out", outDir,
	})
	if err != nil {
		t.Fatalf("expected score CLI to succeed on valid manifest: %v", err)
	}

	scorePath := filepath.Join(outDir, "triage-score.json")
	if _, err := os.Stat(scorePath); err != nil {
		t.Fatalf("triage-score.json was not created: %v", err)
	}
}

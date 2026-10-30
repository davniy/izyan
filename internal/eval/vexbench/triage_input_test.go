package vexbench_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/eval/vexbench"
)

func setupTestTask(t *testing.T) (vexbench.Task, string, string) {
	repos := t.TempDir()
	advisories := t.TempDir()

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

	task := vexbench.Task{
		TaskID:              "k8s-ec78c0f-CVE-2021-3121",
		RepoURL:             "https://github.com/kubernetes/kubernetes",
		CommitSHA:           sha,
		CVEID:               "CVE-2021-3121",
		GroundTruth:         "exploitable",
		GroundTruthCategory: "vulnerable",
		Language:            "go",
		PRURL:               "https://github.com/kubernetes/kubernetes/pull/101154",
	}

	return task, repos, advisories
}

func TestPreparedCaseHasNoLabelFields(t *testing.T) {
	task, repos, advisories := setupTestTask(t)
	bundleDir := t.TempDir()

	prep, err := task.PrepareTriageCase(repos, advisories, bundleDir, nil)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}

	raw, err := json.Marshal(prep)
	if err != nil {
		t.Fatal(err)
	}
	rawStr := string(raw)

	for _, forbidden := range []string{
		"ground_truth",
		"exploitable",
		"vulnerable",
		"pull/101154",
		"k8s-ec78c0f-CVE-2021-3121",
	} {
		if strings.Contains(rawStr, forbidden) {
			t.Fatalf("prepared case bundle leaked label/task info: contains %q in JSON: %s", forbidden, rawStr)
		}
	}
}

func TestTaskIDCannotLeakThroughFindingID(t *testing.T) {
	task, repos, advisories := setupTestTask(t)
	bundleDir := t.TempDir()

	prep, err := task.PrepareTriageCase(repos, advisories, bundleDir, nil)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}

	if prep.FindingID == task.TaskID || strings.Contains(prep.FindingID, "k8s") {
		t.Fatalf("finding ID %q must be opaque and not leak task ID %q", prep.FindingID, task.TaskID)
	}
	if !strings.HasPrefix(prep.FindingID, "vex-") {
		t.Fatalf("expected finding ID prefix vex-, got %q", prep.FindingID)
	}
}

func TestPreparedInputsMatchAcrossProducts(t *testing.T) {
	task, repos, advisories := setupTestTask(t)
	bundleDir := t.TempDir()
	target := &domain.ProductTarget{
		GOOS:   "linux",
		GOARCH: "amd64",
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}

	prep, err := task.PrepareTriageCase(repos, advisories, bundleDir, target)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}

	// Product A and Product B see identical source snapshot and commit
	if prep.ProductAInput.RepoPath != prep.RepoPath {
		t.Fatalf("product A repo path mismatch: got %q want %q", prep.ProductAInput.RepoPath, prep.RepoPath)
	}
	if prep.ProductBInput.Finding.Target.Repository != prep.RepoPath {
		t.Fatalf("product B repo path mismatch: got %q want %q", prep.ProductBInput.Finding.Target.Repository, prep.RepoPath)
	}
	if prep.ProductAInput.CommitSHA != prep.CommitSHA {
		t.Fatalf("product A commit mismatch: got %q want %q", prep.ProductAInput.CommitSHA, prep.CommitSHA)
	}
	if prep.ProductBInput.Finding.Target.Revision != prep.CommitSHA {
		t.Fatalf("product B revision mismatch: got %q want %q", prep.ProductBInput.Finding.Target.Revision, prep.CommitSHA)
	}

	// Advisory digests match
	if len(prep.Investigation.Records) != 1 {
		t.Fatalf("expected 1 captured record, got %d", len(prep.Investigation.Records))
	}
	if prep.Investigation.Records[0].SHA256 != prep.AdvisorySHA {
		t.Fatalf("investigation record SHA mismatch: %q vs %q", prep.Investigation.Records[0].SHA256, prep.AdvisorySHA)
	}
}

func TestPartialAdvisoryStillPreparesForProductB(t *testing.T) {
	repos := t.TempDir()
	advisories := t.TempDir()

	sha := "fdacff08d1a56b0398bcd5d0f7b39e415fd10c09"
	snapDir := filepath.Join(repos, "labstack", "echo", sha)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// An advisory that is Partial (one Go entry usable, another without valid range)
	advContent := `{
		"id": "CVE-2020-26160",
		"modified": "2020-10-01T00:00:00Z",
		"affected": [
			{
				"package": {"name": "github.com/dgrijalva/jwt-go", "ecosystem": "Go"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.2.1"}]}]
			},
			{
				"package": {"name": "github.com/labstack/echo", "ecosystem": "Go"},
				"ranges": []
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(advisories, "CVE-2020-26160.json"), []byte(advContent), 0o644); err != nil {
		t.Fatal(err)
	}

	task := vexbench.Task{
		TaskID:    "echo-fdacff0-CVE-2020-26160",
		RepoURL:   "https://github.com/labstack/echo",
		CommitSHA: sha,
		CVEID:     "CVE-2020-26160",
	}

	bundleDir := t.TempDir()
	prep, err := task.PrepareTriageCase(repos, advisories, bundleDir, nil)
	if err != nil {
		t.Fatalf("partial advisory must prepare successfully for Product B: %v", err)
	}
	if len(prep.Investigation.Records) == 0 {
		t.Fatal("expected captured record in investigation inputs")
	}
	if !prep.Investigation.Records[0].Partial {
		t.Fatal("expected record to be marked Partial")
	}
}

func TestPreparedCaseRejectsSnapshotDrift(t *testing.T) {
	task, repos, advisories := setupTestTask(t)
	bundleDir := t.TempDir()

	prep, err := task.PrepareTriageCase(repos, advisories, bundleDir, nil)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}

	if err := prep.VerifySnapshotDrift(); err != nil {
		t.Fatalf("initial verification should succeed: %v", err)
	}

	// Mutate snapshot file
	mainFile := filepath.Join(prep.RepoPath, "main.go")
	if err := os.WriteFile(mainFile, []byte("package modified\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := prep.VerifySnapshotDrift(); err == nil {
		t.Fatal("expected drift verification failure after snapshot modification")
	} else if !strings.Contains(err.Error(), "drift") {
		t.Fatalf("expected error mentioning drift, got %v", err)
	}
}

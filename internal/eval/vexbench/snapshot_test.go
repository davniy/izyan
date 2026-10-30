package vexbench_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/eval/vexbench"
)

func layoutTask(owner, repo, sha string) vexbench.Task {
	return vexbench.Task{
		TaskID:    "t-1",
		RepoURL:   "https://github.com/" + owner + "/" + repo,
		CommitSHA: sha,
	}
}

func TestLocateSnapshotHappyPath(t *testing.T) {
	repos := t.TempDir()
	sha := "ec78c0f95fbe478f6e7a8f70c2b51ad937d6fa02"
	want := filepath.Join(repos, "kubernetes", "kubernetes", sha)
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := vexbench.LocateSnapshot(repos, layoutTask("kubernetes", "kubernetes", sha))
	if err != nil {
		t.Fatal(err)
	}
	canon, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != canon {
		t.Fatalf("got %q, want canonical %q", got, canon)
	}
}

func TestLocateSnapshotDotGitSuffix(t *testing.T) {
	repos := t.TempDir()
	sha := "fdacff08d1a56b0398bcd5d0f7b39e415fd10c09"
	want := filepath.Join(repos, "labstack", "echo", sha)
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}
	task := layoutTask("labstack", "echo", sha)
	task.RepoURL += ".git"
	if _, err := vexbench.LocateSnapshot(repos, task); err != nil {
		t.Fatalf(".git-suffixed url must resolve: %v", err)
	}
}

func TestLocateSnapshotMissing(t *testing.T) {
	repos := t.TempDir()
	task := layoutTask("owner", "repo", "abc123")
	if _, err := vexbench.LocateSnapshot(repos, task); err == nil {
		t.Fatal("missing snapshot must error")
	}
	if _, err := vexbench.LocateSnapshot(filepath.Join(repos, "no-such"), task); err == nil {
		t.Fatal("missing repos dir must error")
	}
}

func TestLocateSnapshotDotDotEscape(t *testing.T) {
	repos := t.TempDir()
	// The escape target exists, so only the confinement check can stop it.
	outside := filepath.Join(filepath.Dir(repos), "escape", "repo", "abc123")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	task := layoutTask("..", "escape/../repo", "abc123")
	// owner ".." is rejected at the segment check; cover commit-sha too.
	if _, err := vexbench.LocateSnapshot(repos, task); err == nil {
		t.Fatal(".. owner segment must error")
	}
	task = layoutTask("owner", "repo", "..")
	if _, err := vexbench.LocateSnapshot(repos, task); err == nil {
		t.Fatal(".. commit segment must error")
	}
	task = layoutTask("owner", "..", "abc123")
	if _, err := vexbench.LocateSnapshot(repos, task); err == nil {
		t.Fatal(".. repo segment must error")
	}
}

func TestLocateSnapshotSymlinkEscape(t *testing.T) {
	repos := t.TempDir()
	outside := t.TempDir()
	snapshot := filepath.Join(outside, "snapshot")
	if err := os.MkdirAll(snapshot, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repos, "owner")
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	// <repos>/owner/repo is a symlink pointing outside reposDir.
	if err := os.Symlink(outside, filepath.Join(link, "repo")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	task := layoutTask("owner", "repo", "snapshot")
	if _, err := vexbench.LocateSnapshot(repos, task); err == nil {
		t.Fatal("symlink escape out of reposDir must error")
	}
}

func TestLocateSnapshotRejectsGitSegment(t *testing.T) {
	repos := t.TempDir()
	gitDir := filepath.Join(repos, "owner", ".git", "abc123")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	task := layoutTask("owner", ".git", "abc123")
	if _, err := vexbench.LocateSnapshot(repos, task); err == nil {
		t.Fatal(".git segment must error")
	}
}

func TestLocateSnapshotMalformedURL(t *testing.T) {
	repos := t.TempDir()
	for _, raw := range []string{
		"https://github.com/onlyowner",
		"https://github.com/a/b/c",
		"",
		"https://github.com//repo",
	} {
		task := vexbench.Task{TaskID: "t", RepoURL: raw, CommitSHA: "abc"}
		if _, err := vexbench.LocateSnapshot(repos, task); err == nil {
			t.Fatalf("url %q must error", raw)
		}
	}
}

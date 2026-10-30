package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// gitTestRepo creates a real repo with one commit for worktree testing.
func gitTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f.txt")
	run("commit", "-m", "init")
	return dir
}

// TestNewWorktreeConcurrent exercises the serialized add/remove path: N
// goroutines each create and clean up a worktree on the same repo. Without
// the mutex, `git worktree` metadata writes interleave and corrupt or
// deadlock.
func TestNewWorktreeConcurrent(t *testing.T) {
	repo := gitTestRepo(t)
	ctx := context.Background()

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			dir, cleanup, err := NewWorktree(ctx, repo, "HEAD")
			if err != nil {
				errs[k] = err
				return
			}
			if _, err := os.Stat(filepath.Join(dir, "f.txt")); err != nil {
				errs[k] = err
			}
			cleanup()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	// No registered worktrees should remain.
	out, err := exec.Command("git", "-C", repo, "worktree", "list", "--porcelain").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "worktree ") != 1 {
		t.Fatalf("leaked worktree registrations:\n%s", out)
	}
}

// TestWorktreeHelper is the subprocess worker for
// TestNewWorktreeInterProcessLock: it runs one full add/remove cycle and
// exits non-zero on any failure. Never runs as a standalone test.
func TestWorktreeHelper(t *testing.T) {
	if os.Getenv("IZYAN_WORKTREE_HELPER") != "1" {
		t.Skip("helper")
	}
	repo := os.Getenv("IZYAN_WORKTREE_REPO")
	dir, cleanup, err := NewWorktree(context.Background(), repo, "HEAD")
	if err != nil {
		t.Fatalf("helper add: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "f.txt")); err != nil {
		t.Fatalf("helper stat: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("helper cleanup: %v", err)
	}
}

// TestNewWorktreeInterProcessLock proves the OS-level flock: several
// *processes* race worktree add/remove on the same repo — the in-process
// mutex cannot see them, so any metadata corruption or leaked
// registration means the flock failed. git's own worktree writer is not
// consulted here on purpose: the guarantee under test is that concurrent
// analyzers serialize through our lock file.
func TestNewWorktreeInterProcessLock(t *testing.T) {
	repo := gitTestRepo(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestWorktreeHelper$", "-test.v=false")
			cmd.Env = append(os.Environ(), "IZYAN_WORKTREE_HELPER=1", "IZYAN_WORKTREE_REPO="+repo)
			out, err := cmd.CombinedOutput()
			if err != nil {
				errs[k] = fmt.Errorf("child %d: %v\n%s", k, err, out)
			}
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("git", "-C", repo, "worktree", "list", "--porcelain").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "worktree ") != 1 {
		t.Fatalf("leaked worktree registrations:\n%s", out)
	}
}

// TestWorktreeCleanupLockFailureFailsClosed injects a lock-acquisition
// failure at cleanup time: the .git/worktrees removal must NOT run
// unlocked — the cleanup reports ErrWorktreeCleanupSkipped, the
// registration stays for a later locked prune to reconcile, and only the
// temporary directory is removed.
func TestWorktreeCleanupLockFailureFailsClosed(t *testing.T) {
	repo := gitTestRepo(t)
	dir, cleanup, err := NewWorktree(context.Background(), repo, "HEAD")
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// Fail only the cleanup-time acquisition: the add already ran under
	// the real lock. The injected error stands in for any Acquire failure
	// (missing gitdir, EACCES on the lock file, unsupported platform).
	want := errors.New("injected lock failure")
	old := acquireWorktreeLock
	acquireWorktreeLock = func(context.Context, string) (func(), error) {
		return nil, want
	}
	err = cleanup()
	acquireWorktreeLock = old
	if !errors.Is(err, ErrWorktreeCleanupSkipped) {
		t.Fatalf("cleanup error = %v, want ErrWorktreeCleanupSkipped", err)
	}

	// The unlocked remove must not have run: the registration is still
	// there, prunable; the temp dir contents are gone.
	out, _ := exec.Command("git", "-C", repo, "worktree", "list", "--porcelain").CombinedOutput()
	if strings.Count(string(out), "worktree ") != 2 {
		t.Fatalf("expected stale registration to remain for reconcile:\n%s", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("worktree dir should still be removed: %v", err)
	}

	// A later locked mutation reconciles the stale registration.
	if _, err := exec.Command("git", "-C", repo, "worktree", "prune").CombinedOutput(); err != nil {
		t.Fatal(err)
	}
	out, _ = exec.Command("git", "-C", repo, "worktree", "list", "--porcelain").CombinedOutput()
	if strings.Count(string(out), "worktree ") != 1 {
		t.Fatalf("prune did not reconcile stale registration:\n%s", out)
	}
}

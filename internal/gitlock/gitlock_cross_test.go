package gitlock_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/gitlock"
	repoB "github.com/davniy/izyan/internal/productb/repository"
	repoA "github.com/davniy/izyan/internal/repository"
)

// gitTestRepo creates a real repo with one commit for worktree testing.
func gitTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
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

// worktreeCycle runs one full add/read/remove cycle in the named product
// lane: "A" is internal/repository.NewWorktree (Product A), "B" is
// internal/productb/repository.NewWorktree (Product B). Both mutate the
// same .git/worktrees metadata under gitlock.Acquire.
func worktreeCycle(repo, lane string) error {
	var dir string
	var cleanup func() error
	var err error
	switch lane {
	case "A":
		dir, cleanup, err = repoA.NewWorktree(context.Background(), repo, "HEAD")
	case "B":
		dir, cleanup, err = repoB.NewWorktree(context.Background(), repo, "HEAD")
	default:
		return fmt.Errorf("unknown lane %q", lane)
	}
	if err != nil {
		return fmt.Errorf("lane %s add: %w", lane, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "f.txt")); err != nil {
		_ = cleanup()
		return fmt.Errorf("lane %s stat: %w", lane, err)
	}
	return cleanup()
}

// TestCrossProductWorktreeLock is the cross-product serialization proof:
// Product-A and Product-B worktree cycles race on one repository. Without
// the shared gitlock the two lanes' metadata writes interleave — the
// surviving invariant is that every cycle completes and the registry ends
// clean.
func TestCrossProductWorktreeLock(t *testing.T) {
	repo := gitTestRepo(t)

	lanes := []string{"A", "B", "A", "B", "A", "B", "A", "B"}
	var wg sync.WaitGroup
	errs := make([]error, len(lanes))
	for i, lane := range lanes {
		wg.Add(1)
		go func(k int, l string) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if err := worktreeCycle(repo, l); err != nil {
					errs[k] = err
					return
				}
			}
		}(i, lane)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("lane %s worker %d: %v", lanes[i], i, err)
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

// TestWorktreeLaneHelper is the subprocess worker for
// TestCrossProductInterProcessLock: one add/remove cycle in the lane
// named by IZYAN_WT_LANE on IZYAN_WORKTREE_REPO. Never runs standalone.
func TestWorktreeLaneHelper(t *testing.T) {
	if os.Getenv("IZYAN_WORKTREE_HELPER") != "1" {
		t.Skip("helper")
	}
	if err := worktreeCycle(os.Getenv("IZYAN_WORKTREE_REPO"), os.Getenv("IZYAN_WT_LANE")); err != nil {
		t.Fatal(err)
	}
}

// TestCrossProductInterProcessLock proves the lock across *processes* in
// different product lanes: the in-process scheduler cannot see a sibling
// process, so serialization only holds if both lanes' flocks resolve to
// the same file — the guarantee gitlock.Acquire provides.
func TestCrossProductInterProcessLock(t *testing.T) {
	repo := gitTestRepo(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i, lane := range []string{"A", "B", "A", "B"} {
		wg.Add(1)
		go func(k int, l string) {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestWorktreeLaneHelper$", "-test.v=false")
			cmd.Env = append(os.Environ(),
				"IZYAN_WORKTREE_HELPER=1", "IZYAN_WORKTREE_REPO="+repo, "IZYAN_WT_LANE="+l)
			out, err := cmd.CombinedOutput()
			if err != nil {
				errs[k] = fmt.Errorf("lane %s child %d: %v\n%s", l, k, err, out)
			}
		}(i, lane)
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

// TestAcquireSerializes proves flock mutual exclusion directly: two
// sequential Acquire calls on the same repo block each other — a second
// acquisition cannot proceed while the first holds the lock.
func TestAcquireSerializes(t *testing.T) {
	repo := gitTestRepo(t)
	unlock, err := gitlock.Acquire(context.Background(), repo)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// A second acquire on the same repo in a child must block. The child
	// writes a marker only after it wins the lock; if mutual exclusion
	// failed the marker would appear while the parent still holds it.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "marker")
	cmd := exec.Command(exe, "-test.run=^TestAcquireBlocker$", "-test.v=false")
	cmd.Env = append(os.Environ(), "IZYAN_LOCK_HELPER=1", "IZYAN_WORKTREE_REPO="+repo, "IZYAN_LOCK_MARKER="+marker)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Give the child a real window to attempt its acquire: it must not
	// win while the parent still holds the lock.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("child acquired the lock while the parent still held it — no serialization")
		}
		time.Sleep(20 * time.Millisecond)
	}
	unlock()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("blocked child failed to acquire after release: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("marker missing after release — lock was never handed over")
	}
}

// TestAcquireBlocker is the child for TestAcquireSerializes: it acquires
// the repo lock, drops the marker and exits. Never runs standalone.
func TestAcquireBlocker(t *testing.T) {
	if os.Getenv("IZYAN_LOCK_HELPER") != "1" {
		t.Skip("helper")
	}
	unlock, err := gitlock.Acquire(context.Background(), os.Getenv("IZYAN_WORKTREE_REPO"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := os.WriteFile(os.Getenv("IZYAN_LOCK_MARKER"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Package gitlock serializes git worktree metadata mutations across
// processes. .git/worktrees is shared repo state: two analyzer processes
// (Product A internal/repository, Product B internal/productb/repository,
// the remediate command) racing an add against another process's prune or
// remove can each destroy the other's registration. The bound must be
// OS-level, not in-process: this package is the single choke point every
// writer in this codebase funnels through.
package gitlock

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/fedorovmv/izyan/internal/flock"
)

// LockFileName is the lock file inside the repo's git dir. Git itself
// rewrites .git/worktrees under no lock we can rely on, so the filename
// is a repo-local convention shared by every product lane.
const LockFileName = "izyan-worktree.lock"

// Acquire resolves the repo's git dir and takes an exclusive advisory
// file lock on <gitdir>/izyan-worktree.lock for the caller's whole
// worktree add/prune/remove critical section (flock(2) on Unix,
// LockFileEx on Windows — same blocking-exclusion semantics). The
// returned function unlocks and closes the lock file; callers MUST hold
// the lock for the complete mutation — locking only the prune is as
// unsafe as no lock.
//
// The lock is advisory and cooperative: writers that bypass this package
// are outside the contract, which is why every worktree mutation in the
// repository routes here. A non-nil error means NO lock is held — callers
// must not run the git mutation on failure.
func Acquire(ctx context.Context, absRepo string) (func(), error) {
	gitDir, err := absoluteGitDir(ctx, absRepo)
	if err != nil {
		return nil, fmt.Errorf("resolve git dir for worktree lock: %w", err)
	}
	unlock, err := flock.Exclusive(filepath.Join(gitDir, LockFileName), 0o644)
	if err != nil {
		return nil, fmt.Errorf("worktree lock %s: %w", filepath.Join(gitDir, LockFileName), err)
	}
	return unlock, nil
}

func absoluteGitDir(ctx context.Context, absRepo string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--absolute-git-dir")
	cmd.Dir = absRepo
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return filepath.Clean(string(out[:len(out)-1])), nil
}

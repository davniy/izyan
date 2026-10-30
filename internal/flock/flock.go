// Package flock is the codebase's single advisory file-lock primitive.
// Writers take exclusive locks (gitlock worktree metadata, the triage
// run-dir ownership claim and the human-decision collection); readers of
// append-only collections take the non-creating shared lock so inspecting a
// run never modifies it. All behave the same on every OS the CI build matrix
// covers: flock(2) on Unix, LockFileEx on Windows, and an explicit
// fail-closed error anywhere else.
package flock

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrUnsupported marks platforms without a file-lock implementation.
// Callers MUST treat it as fail-closed: the protected mutation does not
// run — it never degrades to an unlocked write.
var ErrUnsupported = errors.New("flock: file locking unsupported on this platform")

// Exclusive takes an exclusive blocking advisory lock on path (creating
// the file when needed) and returns an idempotent unlock that releases
// the lock and closes the descriptor. The lock serializes cooperating
// processes only; writers that bypass this package are outside the
// contract.
//
// On platforms without an implementation (see ErrUnsupported) no file
// is created and no lock is taken.
func Exclusive(path string, perm os.FileMode) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, perm)
	if err != nil {
		return nil, err
	}
	unlock, err := lockFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		unlock()
		f.Close()
	}, nil
}

// Shared takes a shared blocking advisory lock on an existing path and
// returns an idempotent unlock. It never creates the file or its parent
// directory and opens the file read-only: a missing lock is os.ErrNotExist,
// and a read-only lock file is still lockable. Readers use Shared so
// inspecting an append-only collection cannot mutate it.
//
// On platforms without an implementation (see ErrUnsupported) no lock is
// taken.
func Shared(path string) (func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	unlock, err := lockFileShared(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		unlock()
		f.Close()
	}, nil
}

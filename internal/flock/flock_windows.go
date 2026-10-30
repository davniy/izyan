//go:build windows

package flock

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive blocking LockFileEx on byte 0 of the file —
// the Windows analogue of flock(2) LOCK_EX. A zero Overlapped pins the
// range start at offset 0; the same struct must be handed back to
// UnlockFileEx, so it is captured in the closure.
func lockFile(f *os.File) (func(), error) {
	var ov windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov); err != nil {
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ov)
	}, nil
}

// lockFileShared takes a non-exclusive blocking LockFileEx on byte 0 — the
// Windows analogue of flock(2) LOCK_SH. LockFileEx requires a handle with
// GENERIC_READ or GENERIC_WRITE access, so the read-only descriptor from
// Shared is sufficient and the lock file is never written.
func lockFileShared(f *os.File) (func(), error) {
	var ov windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), 0, 0, 1, 0, &ov); err != nil {
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ov)
	}, nil
}

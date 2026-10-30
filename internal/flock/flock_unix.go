//go:build unix

package flock

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive blocking flock(2) on the open file.
func lockFile(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}, nil
}

// lockFileShared takes a shared blocking flock(2) on the open file. It only
// needs a read-only descriptor and never modifies the locked file.
func lockFileShared(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}, nil
}

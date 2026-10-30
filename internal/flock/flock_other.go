//go:build !unix && !windows

package flock

import "os"

// lockFile fails closed on platforms with no implementation: callers get
// ErrUnsupported and the protected mutation never runs unlocked.
func lockFile(*os.File) (func(), error) {
	return nil, ErrUnsupported
}

// lockFileShared fails closed on platforms with no implementation.
func lockFileShared(*os.File) (func(), error) {
	return nil, ErrUnsupported
}

//go:build !unix && !windows

package triage

import "fmt"

// syncDir fails closed on platforms with no directory-sync implementation:
// the writer reports an explicit unsupported-durability error instead of
// claiming a durable record.
func syncDir(path string) error {
	return fmt.Errorf("%w: %s", ErrDirectorySyncUnsupported, path)
}

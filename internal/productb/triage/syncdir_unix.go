//go:build unix

package triage

import "os"

// syncDir fsyncs one directory so a newly created/renamed entry survives a
// crash. The read-only directory descriptor is sufficient for fsync(2).
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

//go:build windows

package triage

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// syncDir flushes a directory handle so a newly created/renamed entry is
// durable. Windows needs FILE_FLAG_BACKUP_SEMANTICS to open a directory and
// GENERIC_WRITE for FlushFileBuffers. A filesystem that rejects the flush is
// reported as an explicit durability error, never as a silent success.
func syncDir(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("human decision: encode directory path %q: %w", path, err)
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("human decision: open directory %s for sync: %w", path, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.FlushFileBuffers(h); err != nil {
		return fmt.Errorf("human decision: sync directory %s: %w", path, err)
	}
	return nil
}

// Package liba is part of a library-only snapshot: no main package
// exists anywhere, so no shipping root can be confirmed.
package liba

import "example.com/scopelib/libb"

// Use drives the only cross-package edge in the snapshot.
func Use() string {
	return libb.Helper()
}

// dead would be unreachable if any root existed — with none it must
// stay UNKNOWN.
func dead() int {
	return 0
}

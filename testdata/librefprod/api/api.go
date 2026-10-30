// Package api belongs to a library-only snapshot: no main package
// exists anywhere, so no shipping root can be confirmed and no package
// may be proven dead. Its module references must be retained as
// evidence — aggressive dead filtering is unsound without a root.
package api

import "example.com/mixdep/lib"

// Handle calls the vulnerable module API from library code.
func Handle() string {
	return lib.Vulnerable()
}

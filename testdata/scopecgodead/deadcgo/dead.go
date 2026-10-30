// Package deadcgo carries a cgo file but is never imported: a dead
// package whose dynamic-link surface must not reopen the scope.
package deadcgo

// Plain keeps the package buildable when cgo is disabled.
func Plain() int { return 1 }

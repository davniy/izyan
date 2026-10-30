//go:build fuzzing

package fuzz

import "example.com/mixdep/lib"

// gatedRef is a build-gated reference inside a dead package — discarded
// into the audit trail, never a blocker.
func gatedRef() string {
	return lib.Vulnerable()
}

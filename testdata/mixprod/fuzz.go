//go:build fuzzing

package main

import "example.com/mixdep/lib"

// gatedRef only compiles under -tags fuzzing: a build-gated reference
// inside the shipping package — a blocker for the current-context proof.
func gatedRef() string {
	return lib.Vulnerable()
}

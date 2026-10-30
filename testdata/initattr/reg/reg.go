// Package reg is linked into the shipping binary only for its init side
// effects: main blank-imports it. The package-level call to Vulnerable
// runs at init even though the dead helper above it never runs.
package reg

import "example.com/mixdep/lib"

// DeadHelper is a shipping-package function nobody calls — DEAD.
// The stale-enc bug once attributed the package-level call below to it.
func DeadHelper() {}

var _ = lib.Vulnerable()

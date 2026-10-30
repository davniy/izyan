// Package entry is the API surface the product imports. Its Run
// function calls a linkname-bound symbol whose real body lives in a
// package nothing imports — invisible to the static import graph.
package entry

import (
	_ "unsafe"
)

//go:linkname hiddenTarget example.com/dynlinkdep/hidden.Target
func hiddenTarget() string

// Used is the benign API the product calls.
func Used() string { return "ok" }

// Run reaches the hidden implementation through the linkname edge.
func Run() string { return hiddenTarget() }

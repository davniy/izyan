// Package fuzz is never imported by the shipping main — a dead product
// package whose calls into the module must not seed reachability.
package fuzz

import "example.com/mixdep/lib"

// Exercise calls the vulnerable module API from dead code.
func Exercise() string {
	return lib.Vulnerable()
}

// init invokes the vulnerable module API from package initialization of
// a package that is never linked — dead init evidence, discarded with
// the package.
func init() {
	_ = lib.Vulnerable()
}

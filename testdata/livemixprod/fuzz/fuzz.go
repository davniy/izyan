// Package fuzz is never imported by the shipping main — a dead product
// package whose call to Vulnerable must be discarded into the audit
// trail while the live main reference keeps the proof open.
package fuzz

import "example.com/mixdep/lib"

// Exercise calls the vulnerable module API from dead code.
func Exercise() string {
	return lib.Vulnerable()
}

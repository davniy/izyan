package main

import (
	"testing"

	"example.com/libassertprod/assert"
)

// TestBaselineEquivalence is the only import path of the assertion library:
// the vulnerable parsing code is linked into the test binary, never into a
// product binary.
func TestBaselineEquivalence(t *testing.T) {
	if !assert.YAMLEq(t, "name: stable\n", "name: stable\n") {
		t.Fatal("baseline documents must compare equal")
	}
}

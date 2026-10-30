package main

import (
	"testing"

	"example.com/usagedep/shared"
	"example.com/usagedep/testonly"
)

// TestProbe links the test-only dep package exclusively through the
// test variant of this root package, while shared stays reachable from
// both the product and the test closures (mixed).
func TestProbe(t *testing.T) {
	if testonly.Name() == "" || shared.Name() == "" {
		t.Fatal("empty dep name")
	}
}

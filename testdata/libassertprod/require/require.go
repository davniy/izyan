// Package require forwards to the public assert API and fails fast.
package require

import "example.com/libassertprod/assert"

// TestingT is the minimal testing interface the require helpers need.
type TestingT interface {
	Errorf(format string, args ...interface{})
}

// YAMLEq fails the test when the two documents differ.
func YAMLEq(t TestingT, expected, actual string) {
	if !assert.YAMLEq(t, expected, actual) {
		t.Errorf("not equal")
	}
}

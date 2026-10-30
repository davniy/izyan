// Package assert is a small stand-in for a public assertion library: both
// operands of a YAML comparison are parsed through the vulnerable dependency.
package assert

import "example.com/dep/vuln"

// TestingT is the minimal testing interface the assertion helpers need.
type TestingT interface {
	Errorf(format string, args ...interface{})
}

type helper interface{ Helper() }

// YAMLEq reports whether expected and actual parse to equal documents. The
// parsing code is shipped library source: only the TestingT implementation
// comes from the caller.
func YAMLEq(t TestingT, expected, actual string) bool {
	if h, ok := t.(helper); ok {
		h.Helper()
	}
	expectedDoc := vuln.ParseBytes([]byte(expected))
	actualDoc := vuln.ParseBytes([]byte(actual))
	if expectedDoc != actualDoc {
		t.Errorf("not equal:\nexpected: %s\nactual:   %s", expected, actual)
		return false
	}
	return true
}

// Package helpers lives in a different module than the advisory subject:
// resolving its exported func-value factory pulls an extras package the
// may-call scan cannot have indexed before the scan starts.
package helpers

import "example.com/dep/vuln"

// GetParser returns the subject symbol as a function value.
func GetParser() func(string) string { return vuln.Parse }

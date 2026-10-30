// Package shared is reachable from both the product and the test
// closures (mixed).
package shared

// Name identifies the package for the fixture's assertions.
func Name() string { return "shared" }

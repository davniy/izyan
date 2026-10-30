// Package testonly is reachable only from the test closure: the
// snapshot imports it exclusively from an _test.go file.
package testonly

// Name identifies the package for the fixture's assertions.
func Name() string { return "testonly" }

// Package unused is a member of the advisory module that no snapshot
// package or test imports: it is absent from both recorded build
// closures.
package unused

// Name identifies the package for the fixture's assertions.
func Name() string { return "unused" }

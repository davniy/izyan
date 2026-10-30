// Package foo shares its directory with a hidden main file: the loader
// reports a conflicting-package error and the loader-visible name is
// "foo", yet the main clause below still produces a binary.
package foo

// F is ordinary code in the conflicted package.
func F() int { return 1 }

// Package util is never imported by the shipping main: a dead product
// package. Even its exported symbols and init are unreachable evidence.
package util

// Orphan is exported yet dead — the package is outside the closure, so
// function-level root rules never apply.
func Orphan() string {
	return "o"
}

func helper() string {
	return "u"
}

func init() {
	_ = helper()
}

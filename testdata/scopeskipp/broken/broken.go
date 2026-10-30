// Package broken fails to type-check; its import edge to nothing
// special keeps recovery simple — what matters is that cmd/app's
// (skipped) import edge to it is recovered, so the package sits inside
// the shipping closure.
package broken

// X is referenced by the shipping main.
var X = undefinedIdentifier

// Package hidden is never imported — a plugin may provide its symbols
// at runtime, so nothing here may be called DEAD.
package hidden

// Target is the vulnerable symbol an advisory names.
func Target() string { return "hit" }

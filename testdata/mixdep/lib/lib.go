// Package lib is a pretend advisory dependency: Used is the API products
// drive; Vulnerable and its callee deadInternal sit behind no live entry.
package lib

// Used is the entry point products actually call.
func Used() string { return "ok" }

// Vulnerable is exported but reachable only from callers outside the
// live module cone.
func Vulnerable() string { return deadInternal() }

func deadInternal() string { return "hit" }

// Apply invokes a func value — opaque dispatch the static graph cannot
// resolve. It is not reached from Used.
func Apply(f func() string) string { return f() }

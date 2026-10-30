// Package hidden is never imported: entry's go:linkname pulls Target
// into the binary without an import edge, so the import-closure cone
// must never call its contents dead.
package hidden

// Target is the vulnerable symbol an advisory names — reachable only
// through go:linkname.
func Target() string { return "hit" }

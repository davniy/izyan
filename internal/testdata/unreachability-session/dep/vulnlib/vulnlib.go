// Package vulnlib is a pretend advisory dependency: OrphanA/OrphanB are the
// declared vulnerable symbols that no code in the snapshot invokes.
package vulnlib

// OrphanA is a pretend affected symbol: declared, exported, never called.
func OrphanA(s string) string { return "a:" + s }

// OrphanB is a second pretend affected symbol used to test multi-subject
// proof completeness.
func OrphanB(n int) int { return n + 1 }

// Benign is the module API the product actually drives — it gives the
// module-internal reachability check a real entry symbol.
func Benign() string { return internal() }

func internal() string { return "ok" }

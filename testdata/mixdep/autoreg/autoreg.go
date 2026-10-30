// Package autoreg runs a package-level call to a lib symbol during its
// init machinery. When the product links autoreg the call is reachable;
// when no shipping package imports it, it is dead module code.
package autoreg

import "example.com/mixdep/lib"

var _ = lib.Vulnerable()

// Wire never runs on its own — the package var above is what matters.
func Wire() {}

// Package deadpkg imports the vendored module but is itself dead.
package deadpkg

import "example.com/vend/vendlib"

func D() int { return vendlib.V() }

// Package lib is a linked product package: reachable from main through
// the import graph. It exercises every function-state kind the scope
// model distinguishes.
package lib

import "example.com/scopeprod/svc"

// registered is set at package initialization — the call to initReg
// runs under the package's init machinery even though no init function
// names it.
var registered = initReg()

func initReg() string {
	return "lib"
}

func init() {
	_ = svc.Dispatch()
}

// OrphanAPI is an exported product API: never called inside the
// snapshot, but conservatively callable from outside the shipping
// boundary — the scope model must not mark it DEAD.
func OrphanAPI() string {
	return "api"
}

// Serve is the product path main actually drives.
func Serve() string {
	trigger()
	return helper()
}

// helper is reachable through Serve.
func helper() string {
	return "h"
}

// trigger holds an unresolved function-value call: `f` may bind pickFn's
// result, and `f()` is a call through a func-typed variable — an opaque
// dispatch the static graph cannot resolve.
func trigger() {
	var f func()
	if registered == "never" {
		f = pickFn()
	}
	if f != nil {
		f()
	}
}

func pickFn() func() {
	return func() {}
}

// indirect is never statically called. The opaque call inside trigger
// is signature-compatible (func()), so indirect's state must be
// UNKNOWN, never DEAD.
func indirect() {}

// deadHelper is never called and never materialized: provably dead
// inside a complete, linked package.
func deadHelper(x int) int {
	return transitDead(x)
}

// transitDead is only called from deadHelper — transitively dead.
func transitDead(x int) int {
	return x + 1
}

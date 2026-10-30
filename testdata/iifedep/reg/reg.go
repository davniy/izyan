// Package reg keeps an immediately-invoked function literal at package
// level: its body runs at init, so calls inside it (including interface
// dispatch) are real module-reachability evidence even though the
// enclosing declaration is a var, not a FuncDecl.
package reg

type I interface{ Target() string }

type T struct{}

// Target is only ever invoked from the IIFE below — an opaque
// func() int call site whose signature cannot match func() string.
func (T) Target() string { return "x" }

var _ = func() int {
	var x I = T{}
	return len(x.Target())
}()

// OK is the benign API the product calls.
func OK() string { return "ok" }

// targetCB is invoked only through func literals — one passed as a
// callback argument to run(), one stored in a package var invoked by a
// later init decl. Neither body executes where it is written, but both
// run inside package init, so init reachability must still see them.
func targetCB(n int) int { return n }

func run(cb func()) { cb() }

var _ = run(func() { _ = targetCB(1) })

var keep = func() { _ = targetCB(2) }

var _ = keep()

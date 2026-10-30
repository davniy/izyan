// Package ghost is never imported by the shipping main: every dynamic
// marker it carries is evidence that cannot execute — proven DEAD.
package ghost

import (
	"reflect"

	"example.com/dep/vuln"
)

// Sink binds the dependency symbol through a function value — dead,
// because the whole enclosing package is unreachable.
var Sink = vuln.Parse

// reflectCall holds a reflect.MethodByName dispatch site. The Connect
// call still materializes vuln.Conn in the product instantiation set
// (instantiation inventory covers dead packages), which makes the
// reflect_method marker subject-relevant — only the dead site closes it.
func reflectCall() {
	c, _ := vuln.Connect("x")
	m := reflect.ValueOf(c).MethodByName("Next")
	_ = m
}

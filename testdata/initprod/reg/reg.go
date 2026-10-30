// Package reg is linked into the shipping binary only through a blank
// import: its init machinery runs, so its calls into the module are
// live product references.
package reg

import "example.com/mixdep/lib"

// init invokes the vulnerable module API at package initialization —
// reachable evidence even though no product function ever names reg.
func init() {
	_ = lib.Vulnerable()
}

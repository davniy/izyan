// Package svc is the shipping product path: main imports it, and it
// imports autoreg whose package init calls lib.Vulnerable — a live
// module-internal caller.
package svc

import (
	_ "example.com/mixdep/autoreg"

	"example.com/mixdep/lib"
)

// Serve drives the benign module API only.
func Serve() string {
	return lib.Used()
}

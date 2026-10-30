// Package helper lives under test/ and imports svc, but nothing
// reachable from main imports it: a proven-dead helper package.
package helper

import "example.com/scopetestprod/svc"

// Exercise is a test-only entrypoint; it can never run in the product.
func Exercise() string {
	return svc.Serve()
}

// Package fuzz is a standalone fuzz helper: it imports svc but is
// never imported by the shipping main.
package fuzz

import "example.com/scopetestprod/svc"

func Exercise() string {
	return svc.Serve()
}

// Package svc is linked by main and also imported by dead helper
// packages — it must stay a member while its dead importers do not.
package svc

func Serve() string {
	return "ok"
}

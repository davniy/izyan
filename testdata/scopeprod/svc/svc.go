// Package svc is reached transitively: lib's init calls Dispatch.
package svc

// Getter is a product-declared interface whose dispatch sites resolve
// through the shared interface-impl linking.
type Getter interface {
	get() string
}

// G is materialized at package level — impl is instantiated, so
// receiver-instantiation narrowing keeps the impl edge.
var G Getter = impl{}

type impl struct{}

// get is reachable only through interface dispatch on G — a may edge,
// never proven live, never provably dead.
func (impl) get() string {
	return "g"
}

// Dispatch issues the interface call.
func Dispatch() string {
	return G.get()
}

// unused is a dead unexported helper in a linked package.
func unused() int {
	return 7
}

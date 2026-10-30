// Package box is a pretend advisory dependency exposing a generic
// receiver: the vulnerable symbol is a method on Box[T], reachable only
// when product code instantiates and invokes it.
package box

// Box is a generic container type.
type Box[T any] struct {
	V T
}

// Vuln is the pretend affected symbol — a method on the generic
// receiver.
func (b Box[T]) Vuln() T {
	return b.V
}

// Orphan is a second generic-receiver method no product code calls.
func (b Box[T]) Orphan(a, b2, c int) int {
	return a
}

// NewBox constructs a Box — the benign entry products drive.
func NewBox[T any](v T) Box[T] {
	return Box[T]{V: v}
}

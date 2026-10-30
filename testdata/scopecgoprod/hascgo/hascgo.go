// Package hascgo links into main through cgo — a reachable package the
// static import graph cannot fully describe.
package hascgo

/*
#include <stdlib.h>
*/
import "C"

// Run calls into C.
func Run() int {
	return int(C.abs(-2))
}

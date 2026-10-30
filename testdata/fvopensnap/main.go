package main

import (
	"fmt"

	_ "example.com/fvdep/vuln"
)

// handlers is empty at runtime and its candidate set never resolves: the
// signature-compatible call below stays an unresolved may-caller of
// fvdep vuln.Parse — the may-call enumeration is open, never
// empty-closed.
var handlers = map[string]func(string) string{}

func main() {
	h := handlers["k"]
	fmt.Println(h("x"))
}

package main

import (
	"fmt"
	"os"

	_ "example.com/dep/vuln"
)

// handlers is empty: the candidate set of h resolves to nothing the index
// can prove, so the signature-compatible call below stays an unresolved
// may-caller of vuln.Parse — the enumeration is open, never empty-closed.
var handlers = map[string]func(string) string{}

// apply is the closed control: its func-valued parameter is supplied by
// exactly one resolvable caller argument (os.Getenv).
func apply(f func(string) string, s string) string { return f(s) }

func main() {
	h := handlers["k"]
	fmt.Println(h("x"), apply(os.Getenv, "HOME"))
}

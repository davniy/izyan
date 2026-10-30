package main

import (
	"fmt"

	_ "example.com/dep/vuln"
	"example.com/depfv/helpers"
)

// The vulnerable symbol is invoked through a function value returned by a
// dependency helper in a different module: resolving the candidate set
// grows the extras set mid-scan, so the enumeration must settle before it
// can close — and the site it lands on is a real (non-possible) caller.
func main() {
	g := helpers.GetParser()
	fmt.Println(g("x"))
}

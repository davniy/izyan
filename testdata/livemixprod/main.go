package main

import (
	"fmt"

	"example.com/mixdep/lib"
)

// main calls both the benign API and the vulnerable symbol directly —
// a live product reference that must always block the proof.
func main() {
	fmt.Println(lib.Used(), lib.Vulnerable())
}

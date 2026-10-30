package main

import (
	"fmt"

	"example.com/gendep/box"
)

// main calls the generic-receiver method through a concrete
// instantiation — a live product reference that must be retained.
func main() {
	fmt.Println(box.NewBox[int](0).Vuln())
}

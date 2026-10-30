package main

import (
	"fmt"

	_ "example.com/initprod/reg"

	"example.com/mixdep/lib"
)

// main drives only the benign module API; the blank import links reg,
// whose package init calls the vulnerable symbol — a live product-side
// init reference that must block the proof.
func main() {
	fmt.Println(lib.Used())
}

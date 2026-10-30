package main

import (
	"fmt"

	"example.com/mixdep/lib"
)

// main drives only the benign module API; the fuzz helper below is never
// linked into the shipping binary.
func main() {
	fmt.Println(lib.Used())
}

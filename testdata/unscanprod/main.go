package main

import (
	"fmt"

	"example.com/unreachdep/vulnlib"
)

// main drives only the benign module API; the sibling `bad` package
// cannot even be parsed, so its imports are unrecoverable and no
// reachability verdict may rest on them.
func main() {
	fmt.Println(vulnlib.Benign())
}

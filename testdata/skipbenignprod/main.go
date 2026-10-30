package main

import (
	"fmt"

	"example.com/unreachdep/vulnlib"
)

// main drives only the benign module API; the declared vulnerable symbols
// stay unreachable inside the recorded scope.
func main() {
	fmt.Println(vulnlib.Benign())
}

package main

import (
	"example.com/scopeprod/lib"
	"fmt"
)

// main drives only the linked product packages; the sibling `util`
// package is never imported and stays outside the shipping closure.
func main() {
	fmt.Println(lib.Serve())
}

package main

import (
	"fmt"

	"example.com/scopetestprod/svc"
)

// main drives only svc; test/helper, fuzz and test/bad are never
// imported and stay outside the shipping closure.
func main() {
	fmt.Println(svc.Serve())
}

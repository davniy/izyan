// Command tool is a second product root with no test files: the dep
// package it imports is reachable from the product closure only.
package main

import (
	"fmt"

	"example.com/usagedep/prod"
)

func main() {
	fmt.Println(prod.Name())
}

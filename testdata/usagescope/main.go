package main

import (
	"fmt"

	"example.com/usagedep/shared"
)

// main exercises the shared dep package: it is reachable from both the
// product closure (this root) and the test closure (this root's test
// variant in main_test.go). The product-only dep package is imported
// exclusively by cmd/tool — a product root with no test variant — so
// it stays absent from the test closure. Together the four packages of
// example.com/usagedep cover every B41 class (product, mixed,
// test-only, unknown) under one snapshot.
func main() {
	fmt.Println(shared.Name())
}

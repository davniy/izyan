package main

import (
	"fmt"

	"example.com/scopegen/box"
)

// main drives the box package: a generic instantiation, an interface
// dispatch and an unresolved func-value call — the three shapes whose
// materialization rules keep generic/interface reachability UNKNOWN.
func main() {
	fmt.Println(box.Run())
}

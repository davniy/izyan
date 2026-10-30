// Command app is the shipping main — it imports the broken package, so
// the binary's entry cone reaches code whose type-check failed. Both
// this main and broken stay skipped packages, but the closure must
// treat them as reachable evidence.
package main

import (
	"example.com/scopeskipp/broken"
	"fmt"
)

func main() {
	fmt.Println(broken.X)
}

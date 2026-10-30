// Command app is the shipping main — it imports the broken package, so
// the binary's entry cone reaches code whose type-check failed. The main
// itself fails to type-check, but a failed main is still a shipping root.
package main

import (
	"fmt"

	"example.com/skiplinkprod/broken"
)

func main() {
	fmt.Println(broken.X)
}

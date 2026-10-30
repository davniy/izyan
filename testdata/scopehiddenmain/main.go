package main

import "fmt"

// main is the declared root; the sibling `hidden` directory mixes a
// non-main clause with a hidden package main file, so the loader drops
// it — the clause scan must still find the main and root it.
func main() {
	fmt.Println("ok")
}

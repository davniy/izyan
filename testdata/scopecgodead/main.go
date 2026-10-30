package main

import "fmt"

// main links no cgo; the sibling deadcgo package is never imported.
func main() {
	fmt.Println("ok")
}

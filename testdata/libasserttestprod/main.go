// Command libasserttestprod ships a binary whose production closure never
// links the assertion library: only its test scope imports it.
package main

import "fmt"

func main() {
	fmt.Println("libasserttestprod")
}
